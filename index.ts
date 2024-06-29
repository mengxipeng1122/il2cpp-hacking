

import 'frida-il2cpp-bridge'
// import "ts-frida"

import {
    parseVector2,
    parseVector2Array,
    getUnityVersion,
    parseSystem_Collections_Generic_List,
    parseInt32Arrray,
    listTextures,
    listGameObjects,
    dumpCurrentScene,
} from './il2cppUtils.js'

const il2cpp_hook = ()=>{
    const Assembly_CSharp = Il2Cpp.domain.assembly('Assembly-CSharp');
    Il2Cpp.trace(false)
        .assemblies(Assembly_CSharp)
        //.filterClasses(c=>!c.name.includes('GuruFramework'))
        .and()
        .attach()
}

const soname = 'libil2cpp.so'

const il2cpp_main = ()=>{

    console.log(soname, JSON.stringify(MyFrida.getELFInfoInModule(soname)))

    Il2Cpp.perform(()=>{

        console.log(`Unity version: ${Il2Cpp.unityVersion}`)

        // Il2Cpp.dump('Unity.dump.cs');

        // il2cpp_hook();

    })

}

const main = ()=>{
    Process.enumerateModules()
        // .filter(m=>m.name.includes('coco'))
        .forEach(m=>{
            console.log(JSON.stringify(m))
        })

}

console.log('##################################################')


// Ensure ObjC API is available
if (ObjC.available) {
    const mainBundle = ObjC.classes.NSBundle.mainBundle();
    const bundleIdentifier = mainBundle.bundleIdentifier();
    
    // Convert Objective-C NSString to JavaScript string
    const packageName = bundleIdentifier.toString();
    
    console.log(`Package Name (Bundle Identifier): ${packageName}`);
} else {
    console.error('Objective-C runtime is not available.');
}


// check 


// main();

if (Java.available) Java.perform(il2cpp_main)
else il2cpp_main()
