
import * as path from 'path'

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

import {
    mod as patchlibinfo
} from '../modinfos/libmodpatchgame.js'

const il2cpp_hook = ()=>{
    const Assembly_CSharp = Il2Cpp.domain.assembly('Assembly-CSharp');
    Il2Cpp.trace(false)
        .assemblies(Assembly_CSharp)
        .and()
        .attach()
}


const soname = 'libil2cpp.so'

const dumpGameplayManager = () =>{

    const Yolo_GameplayManager = Il2Cpp.domain.assembly('Assembly-CSharp').image
        .class('Yolo.GameplayManager');
    
    const gameplayManager = Yolo_GameplayManager.field('Instance').value as Il2Cpp.Object;

    console.log(`gameplayManager: ${gameplayManager}`)

    gameplayManager.field('currentHealth').value = 3;
    const currentHealth = gameplayManager.field('currentHealth').value as number;
    console.log(`Current Health: ${currentHealth}`)

}

const dumpUserData = () =>{

    const Yolo_UserData = Il2Cpp.domain.assembly('Assembly-CSharp').image
        .class('Yolo.UserData');
    
    Yolo_UserData.method('set_Coin').invoke(999999);
    const coin = Yolo_UserData.method('get_Coin').invoke() as number;
    console.log(`Coin: ${coin}`)

    Yolo_UserData.method('set_Hint').invoke(999999);
    const hint = Yolo_UserData.method('get_Hint').invoke() as number;
    console.log(`Hint: ${hint}`)

    Yolo_UserData.method('set_NoAdsShown').invoke(true);
    const noAdsShown = Yolo_UserData.method('get_NoAdsShown').invoke() as boolean;
    console.log(`NoAdsShown: ${noAdsShown}`)

    const allVersionsString = Yolo_UserData.method('GetAllVersionsAsString').invoke() as Il2Cpp.String;
    console.log(`AllVersionsAsString: ${allVersionsString.toString()}`)

}


const il2cpp_main = ()=>{

    const patchlib = patchlibinfo.load(
        path.join('/data/local/tmp', 'libpatchgame.so'),
        [
            soname,
        ],
        {
            ... MyFrida.frida_symtab,
        }
    )

    if(0) {
        new NativeFunction(patchlib.symbols.init,'int',[])();
    }


    const appInfo = MyFrida.androidAppInfo();
    console.log(JSON.stringify(appInfo))

    const dumpDir = `${appInfo.externalFilesDir}/dumps/`

    const m = Process.getModuleByName(soname);
    console.log(m.path)
    let sobuffer :ArrayBuffer | null = null;
    if(m.path.split('!').length==2){
        let [zipfile, zipentry] = m.path.split('!');
        if(zipentry.startsWith('/')) zipentry = zipentry.substring(1);
        sobuffer = MyFrida.minizReadEntryFromZipfile(zipfile, zipentry, patchlib);
    }
    else{
        sobuffer = MyFrida.readFileData(m.path);
    }

    if(sobuffer==null) throw new Error(`can not read file: ${m.path}`);

    console.log(soname, JSON.stringify(MyFrida.getELFInfo(sobuffer)))

    Il2Cpp.perform(()=>{

        // Il2Cpp.dump('Unity.dump.cs');

        console.log(`Unity Version: ${getUnityVersion()}`);

        il2cpp_hook();

        // listTextures(dumpDir);

        dumpUserData();

        // dumpGameplayManager();

    })

}


console.log('##################################################')
Java.perform(il2cpp_main)

