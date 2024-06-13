

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
} from './il2cppUtils.js'

const il2cpp_hook = ()=>{
    const Assembly_CSharp = Il2Cpp.domain.assembly('Assembly-CSharp');
    Il2Cpp.trace(false)
        .assemblies(Assembly_CSharp)
        .and()
        .attach()
}
const parseLevelData = (levelData:Il2Cpp.Object)=>{
    const ID            = levelData.field("ID"          ).value;
    const DiffCount     = levelData.field('DiffCount'   ).value;
    const DesignSize    = parseVector2(levelData.field('DesignSize'  ).value as Il2Cpp.Object);
    const DiffPos       = parseVector2Array(levelData.field("DiffPos"     ).value as Il2Cpp.Array);
    const DiffFramePos  = parseVector2Array(levelData.field("DiffFramePos").value as Il2Cpp.Array);

    return {
        ID            ,
        DiffCount     ,
        DesignSize    ,
        DiffPos       ,
        DiffFramePos  ,

    }

}
      


const dumpMainLevelManager = ()=>{

    const MainLevelManager = Il2Cpp.domain.assembly("Assembly-CSharp").image
        .class('MainLevelManager');

    const mainLevelManager = MainLevelManager.method('get_Instance').invoke() as Il2Cpp.Object;

    const ConfigName = (mainLevelManager.field('ConfigName').value as Il2Cpp.String).toString();

    console.log(`ConfigName: ${ConfigName}`)

    const maxLevel = mainLevelManager.method('get_MaxLevel').invoke() as number;

    console.log(`Max level: ${maxLevel}`)

    for(let n=1; n < maxLevel; n++) {
        console.log(n)
        const levelID = (mainLevelManager.method('GetLevelID').invoke(n) as Il2Cpp.String).toString();
        const packageLevelID = (mainLevelManager.method('GetPackageLevelID').invoke(n) as Il2Cpp.String).toString();

        console.log(n, levelID, packageLevelID)
    }



}

const dumpLevelManager = ()=>{

    const LevelManager = Il2Cpp.domain.assembly("Assembly-CSharp").image
        .class('LevelManager');

    const levelManager = LevelManager.method('get_Instance').invoke() as Il2Cpp.Object;

    console.log(`Level Manager: ${levelManager}`)

    console.log(`_DiffNum: ${levelManager.field('_DiffNum').value as number}`)
    console.log(`GameCurrentTime: ${levelManager.field('GameCurrentTime').value as number}`)
    console.log(`_GameFindDiffNum: ${levelManager.field('_GameFindDiffNum').value as number}`)
    console.log(`_levelLife: ${levelManager.field('_levelLife').value as number}`)

    const levelData = levelManager.method('get_LevelData').invoke() as Il2Cpp.Object;
    console.log(`Level Data: ${JSON.stringify(parseLevelData(levelData))}`)

    console.log(`Level Type: ${levelManager.method('get_LevelType').invoke()}`)
    console.log(`Level ID: ${levelManager.method('get_LevelID').invoke()}`)
    console.log(`Level Name: ${levelManager.method('get_LevelName').invoke()}`)
    console.log(`Level Category: ${levelManager.method('get_LevelCategory').invoke()}`)
    console.log(`Level : ${levelManager.method('get_Level').invoke()}`)
    console.log(`Level cost time: ${levelManager.method('get_LevelCostTime').invoke()}`)
    console.log(`Actually game time: ${levelManager.method('get_ActuallyGameTime').invoke()}`)



}

const soname = 'libil2cpp.so'


const il2cpp_main = ()=>{

    console.log(soname, JSON.stringify(MyFrida.getELFInfoInModule(soname)))


    // console.log(JSON.stringify(MyFrida.androidAppInfo()))
    Il2Cpp.perform(()=>{
        // Il2Cpp.dump('dump.cs');
        console.log(`Unity Version: ${getUnityVersion()}`)

        // il2cpp_hook();

        // dumpMainLevelManager();

        dumpLevelManager();

    })

}


console.log('##################################################')
Java.perform(il2cpp_main)

