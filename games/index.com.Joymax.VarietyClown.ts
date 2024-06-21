

import 'frida-il2cpp-bridge'
// import "ts-frida"

import {
    C,
    dumpCurrentScene,
    dumpScenes,
    listGameObjects,
    listMeshes,
    listTextures,
} from '../il2cppUtils.js'

const il2cpp_hook = ()=>{
    const Assembly_CSharp = Il2Cpp.domain.assembly('Assembly-CSharp');
    Il2Cpp.trace()
        .assemblies(Assembly_CSharp)
        //.filterClasses(c=>!c.name.includes('GuruFramework'))
        .and()
        .attach()
}

const dumpResources = ()=>{
    const UnityEngine_Object = C("UnityEngine.CoreModule",'UnityEngine.Object');
    const UnityEngine_Resources = C("UnityEngine.CoreModule",'UnityEngine.Resources');
    const UnityEngine_AudioClip = C("UnityEngine.AudioModule",'UnityEngine.AudioClip');


    const allAudioClips = UnityEngine_Resources.method('FindObjectsOfTypeAll')
        .overload('System.Type')
        .invoke(UnityEngine_AudioClip.type.object) as Il2Cpp.Array;
    console.log(`All audioclip: ${allAudioClips.length}`)


    for(const item of allAudioClips) {
        const audioClip = item as Il2Cpp.Object;
        console.log(audioClip.toString())
        const length = audioClip.method('get_length').invoke() as number;
        console.log(`length: ${length}`)
        const loadAudioDataDone = audioClip.method('LoadAudioData').invoke() as boolean;
        console.log(`loadAudioDataDone: ${loadAudioDataDone}`)
    }


// 34582     static UnityEngine.Object[] FindObjectsOfTypeAll(System.Type type); // 0x0059209c                                                      
// 34583     static T[] FindObjectsOfTypeAll();    
}

const il2cpp_main = ()=>{


    Il2Cpp.perform(()=>{

        console.log(`Unity version: ${Il2Cpp.unityVersion}`)

        // Il2Cpp.dump('Unity.dump.cs');

        // il2cpp_hook();

        dumpResources();

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

if(Java.available) Java.perform(il2cpp_main)
else il2cpp_main()

// main();

