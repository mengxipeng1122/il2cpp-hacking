

import 'frida-il2cpp-bridge'
import "ts-frida"

import {
    parseVector2,
    parseVector2Array,
    getUnityVersion,
    parseSystem_Collections_Generic_List,
    parseInt32Arrray,
    listTextures,
    listGameObjects,
    dumpCurrentScene,
} from '../il2cppUtils.js'

const il2cpp_hook = ()=>{
    const Assembly_CSharp = Il2Cpp.domain.assembly('Assembly-CSharp');
    Il2Cpp.trace(false)
        .assemblies(Assembly_CSharp)
        .and()
        .attach()
}


const soname = 'libil2cpp.so'


const il2cpp_main = ()=>{

    const appInfo = MyFrida.androidAppInfo();
    console.log(JSON.stringify(appInfo))

    const dumpDir = `${appInfo.externalFilesDir}/dumps/`


    console.log(soname, JSON.stringify(MyFrida.getELFInfoInModule(soname)))
    const m = Process.getModuleByName(soname);
    console.log(m.path)

    Il2Cpp.perform(()=>{

        // Il2Cpp.dump('Unity.dump.cs');

        console.log(`Unity Version: ${getUnityVersion()}`)

        console.log(`Game objects: ${JSON.stringify(listGameObjects())}`);

        // il2cpp_hook();

        // listTextures(dumpDir);


    })

}


console.log('##################################################')
Java.perform(il2cpp_main)

