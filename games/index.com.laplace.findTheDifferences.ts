

import 'frida-il2cpp-bridge'
// import "ts-frida"

import {
    C,
    dumpCurrentScene,
    dumpScenes,
    listGameObjects,
    listMeshes,
    listTextures,
    showIl2cppInstances,
} from '../il2cppUtils.js'

const il2cpp_hook = ()=>{
    const Assembly_CSharp = Il2Cpp.domain.assembly('Assembly-CSharp');
    Il2Cpp.trace()
        .assemblies(Assembly_CSharp)
        //.filterClasses(c=>!c.name.includes('GuruFramework'))
        .and()
        .attach()
}

const dumpLevelContext = ()=>{
    const UnityEngine_Object = C("UnityEngine.CoreModule","UnityEngine.Object");
    const LevelContext = C("Assembly-CSharp", "LevelContext");

    const levelContexts = UnityEngine_Object.method('FindObjectsOfType')
        .overload("System.Type", "System.Boolean")
        .invoke(LevelContext.type.object, true) as Il2Cpp.Array;
    if(levelContexts.length>0){
        const levelContext = levelContexts.get(0) as Il2Cpp.Object;
        console.log(`Level Context: ${levelContext}`);
        showIl2cppInstances(levelContext);

        const _gameplayData = levelContext.field('_gameplayData').value as Il2Cpp.Object;
        showIl2cppInstances(_gameplayData);
    }

}

const il2cpp_main = ()=>{


    Il2Cpp.perform(()=>{

        console.log(`Unity version: ${Il2Cpp.unityVersion}`)

        // Il2Cpp.dump('Unity.dump.cs');

        dumpLevelContext();

        // il2cpp_hook();


        // console.log(`dump scenes: ${JSON.stringify(dumpScenes())}`)

        // console.log(`Game Objects: ${JSON.stringify(listGameObjects())}`)
        // console.log(`Current scene: ${JSON.stringify(dumpCurrentScene(true))}`)
        // dumpCurrentScene(true);

        // listTextures();
        // listMeshes();

    })

}

const main = ()=>{
    Process.enumerateModules()
        .filter(m=>m.name.includes('coco'))
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

if(Java.available) Java.perform(il2cpp_main)
else il2cpp_main()

