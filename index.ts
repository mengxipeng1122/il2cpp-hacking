

import 'frida-il2cpp-bridge'
import "ts-frida"

import {
    dumpCurrentScene,
    dumpScenes,
    listGameObjects,
    listMeshes,
    listTextures,
} from './il2cppUtils.js'

const il2cpp_hook = ()=>{
    const Assembly_CSharp = Il2Cpp.domain.assembly('Assembly-CSharp');
    Il2Cpp.trace()
        .assemblies(Assembly_CSharp)
        .filterClasses(c=>!c.name.includes('GuruFramework'))
        .and()
        .attach()
}

const il2cpp_main = ()=>{

    // console.log(JSON.stringify(MyFrida.androidAppInfo()))
    Il2Cpp.perform(()=>{
        // Il2Cpp.dump('dump.cs');

        il2cpp_hook();

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
Java.perform(il2cpp_main)

