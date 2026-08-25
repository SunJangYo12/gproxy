/*
 * move this script to <template>/src and npm run build
*/


import "frida-il2cpp-bridge";

declare const rpc: any;
declare const Il2cpp: any;

class MyClass
{
    typeLog: string;

    constructor() {
       this.rpc_setup();
       this.typeLog = "send";
    }

    rpc_setup()
    {
        rpc.exports = {
           assemblylist: (): void => {

               Il2Cpp.perform(() => {
                   let output: string[] = [];

                   Il2Cpp.domain.assemblies.forEach(a => {
                       if (a.name !== null)
                           output.push(a.name);
                   });
                   send({"type": "enumunity_assembly", "log": output});
               });
           },
           assemblydump: (): void => {
               Il2Cpp.dump();
           },
           assemblytrace: (masm: string, wparam: string): void => {

               Il2Cpp.perform(() => {
                   console.log("[+] Agent: start hooking... "+masm);

                   const image = Il2Cpp.domain.assembly(masm).image;
                   let result: string[] = [];

                   image.classes.forEach(klass => {
                       if (wparam == "y")
                           Il2Cpp.trace(true).classes(klass).and().attach();
                       else
                           Il2Cpp.trace().classes(klass).and().attach();


                       /*klass.methods.forEach(m => {

                           result.push(`${klass.namespace}.${klass.name}::${m.name}(${m.parameterCount})`);
                       });*/
                   });
                   //send({"type": "enumunity_method", "log": result});

                   console.log("[+] Agent: hook complete. ");
               });
           }
        };
    }
}

const f = new MyClass();
rpc.exports.fuzzer = f;

/*
Il2Cpp.perform(() => {
	Il2Cpp.trace(true)
		.assemblies(Il2Cpp.domain.assembly("Assembly-CSharp"))
		.and()
		.attach()
});*/


/*
Il2Cpp.perform(() => {
	const SystemString = Il2Cpp.corlib.class("System.String");
	//	.filterMethods(method => method.isStatic && method.returnType.equals(SystemString.type) && !method.isExternal)

	Il2Cpp.trace()
		.classes(SystemString)
		.and()
		.attach();
});
*/

/*
Il2Cpp.perform(function(){

	const AssemblyCSharp = Il2Cpp.domain.assembly("Assembly-CSharp").image

	console.log(AssemblyCSharp.isNull)

})*/
