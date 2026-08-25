import "frida-il2cpp-bridge";

console.log("czzzzzzzzzzzz");


class GlobalState {
    private gdb_functions: Record<string, { count: number; time: number }>;

    constructor() {
        this.gdb_functions = {};
    }

    append_gdbfunc(s: string): void {
        const now = Date.now() / 1000; // supaya formatnya detik seperti time.time()

        if (this.gdb_functions[s]) {
            this.gdb_functions[s].count += 1;
            this.gdb_functions[s].time = now + 3;
        } else {
            this.gdb_functions[s] = {
                count: 1,
                time: now + 3
            };
        }
    }

    getState() {
        return this.gdb_functions;
    }
}


(globalThis as any).IL2CPP_UNITY_VERSION = "6000.0.59f2";


Il2Cpp.perform(() => {

   // list assembly
   //Il2Cpp.domain.assemblies.forEach(ass => {
   //   console.log(ass.name)
   //});

   console.log(Il2Cpp.unityVersion)

/*
   const AssemblyCSharp = Il2Cpp.domain.assembly("Assembly-CSharp").image

   const total: number = AssemblyCSharp.classes.length
   let count: number = 0

   console.log("======= start hooking")
   AssemblyCSharp.classes.forEach(cls => {

       console.log(`[${count}/${total}] ${cls.namespace}...${cls.name}`);

       Il2Cpp.trace().classes(cls).and().attach()
       count += 1
   })
   console.log("======= done hooking")*/




//   Il2Cpp.trace().classes(...AssemblyCSharp.classes).and().attach()

/*
   console.log("[] Starting hook")

   let done: boolean = false

   // list class
   const AssemblyCSharp = Il2Cpp.domain.assembly("Assembly-CSharp").image
   AssemblyCSharp.classes.forEach(cls => {

      //console.log(cls.namespace+"."+cls.method);

      let total: number = 0;
      let fail_hook: number = 0;

      cls.methods.forEach(m => {

         if (!m.virtualAddress.isNull())
         {
            total += 1;
            try{
               const classmethod = `${cls.name}.${m.name}`;

               const aa = new GlobalState();

               Interceptor.attach(m.virtualAddress, {
                  onEnter: function(args) {
                     //if (!done) return;

                     aa.append_gdbfunc(classmethod);

                     console.log(JSON.stringify(aa.getState(), null, 2) );
                  }
               });
            } catch (e: any) {
               fail_hook +=1;
               //console.log("SKIP: "+cls.namespace+"..."+m)
            }
         }
      });

      console.log(`[${fail_hook}/${total}] ${cls.namespace}..${cls.name}`)
   });
   console.log("End hook")
   done = true
*/
});

