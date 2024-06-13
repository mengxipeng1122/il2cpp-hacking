

import 'frida-il2cpp-bridge'
import 'ts-frida'

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
        .and()
        .attach()
}

const main = ()=>{

    Il2Cpp.perform(()=>{
        // Il2Cpp.dump('dump.cs')

        //il2cpp_hook();

        // console.log(`dump scenes: ${JSON.stringify(dumpScenes())}`)

        // console.log(`Game Objects: ${JSON.stringify(listGameObjects())}`)
        // console.log(`Current scene: ${JSON.stringify(dumpCurrentScene(true))}`)
        // dumpCurrentScene(true);

        //listTextures();
        listMeshes();

    })

}

console.log('##################################################')
Java.perform(main)

