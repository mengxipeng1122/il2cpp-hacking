

import 'frida-il2cpp-bridge'
import "ts-frida"

import {
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


const parseLevelData = (LevelData:Il2Cpp.Object) =>{

    const puzzle_id = (LevelData.method('get_puzzle_id').invoke() as Il2Cpp.String) .toString();

    const tubesList = parseSystem_Collections_Generic_List(LevelData.method('get_tubes').invoke() as Il2Cpp.Object);
    const stepsList = parseSystem_Collections_Generic_List(LevelData.method('get_steps').invoke() as Il2Cpp.Object);


    const tubes = tubesList.map(item=> parseInt32Arrray(item as Il2Cpp.Array))
    const steps = stepsList.map(item=> parseInt32Arrray(item as Il2Cpp.Array))

    return {
        puzzle_id,
        tubes,
        steps,
    }
}

const parseStageData = (stageData:Il2Cpp.Object)=>{

    const stage_id = (stageData.method('get_stage_id').invoke() as Il2Cpp.String).toString();
    const levelsList = parseSystem_Collections_Generic_List(
        stageData.method('get_levels').invoke() as Il2Cpp.Object
    )

    const levels = levelsList.map(item=> parseLevelData(item) )

    return {
        stage_id,
        levels,
    }
}

const dumpLevelData = ()=>{

    const GameManager = Il2Cpp.domain.assembly('Assembly-CSharp').image
        .class('GameManager');

    console.log(`Game Manager ${GameManager}`);

    const gameManager = GameManager.method('get_Instance').invoke() as Il2Cpp.Object;
    console.log(`instance ${gameManager}`);

    const Title = gameManager.field('Title').value as Il2Cpp.Object;
    const m_Text = Title.field('m_Text').value as Il2Cpp.String;
    const Skip = gameManager.field('Skip').value as boolean;

    console.log(Title, Skip, m_Text.toString());

    const LevelData = gameManager.method('GetLevelData').invoke() as Il2Cpp.Object
    console.log(`Lelve data: ${JSON.stringify(parseLevelData(LevelData))}`)


}

const dumpAllLevelData = ()=>{

    const GuruFramework_Level_ActivityLevelMgr = Il2Cpp.domain.assembly('Assembly-CSharp').image
        .class('GuruFramework.Level.ActivityLevelMgr');

    const activityLevelMgr = GuruFramework_Level_ActivityLevelMgr.method('get_Instance').invoke() as Il2Cpp.Object;
    console.log(`Activity levelMgr: ${activityLevelMgr}`)

    const _stages = activityLevelMgr.field('_stages') .value as Il2Cpp.Array;
    console.log(`Stages: ${_stages.length}`)
    for(const item of _stages){
        const stageData = item as Il2Cpp.Object;
        const stage_id = (stageData.method('get_stage_id').invoke() as Il2Cpp.String).toString();
        const levels = parseSystem_Collections_Generic_List(
            stageData.method('get_levels').invoke() as Il2Cpp.Object
        )
        console.log(`Stage id: ${stage_id}`);
        levels.forEach(e=>{
            console.log(`${JSON.stringify(parseLevelData(e))}`)

        })
    }
}

const dumpAllLevelData1 = ()=>{
    const GuruFramework_Level_LevelMgr = Il2Cpp.domain.assembly('Assembly-CSharp').image
        .class('GuruFramework.Level.LevelMgr');
    const levelMgr = GuruFramework_Level_LevelMgr.method('get_Instance').invoke() as Il2Cpp.Object;


    const _curStage = levelMgr.field('_curStage').value as Il2Cpp.Object;
    console.log(`_curStage         : ${JSON.stringify(parseStageData(_curStage))} `);


    const _stageIndex = levelMgr.field('_stageIndex').value as number;
    const _stageStartLevel = levelMgr.field('_stageStartLevel').value as number;
    const _stageEndevel = levelMgr.field('_stageEndLevel').value as number;
    console.log(`_stageIndex         : ${_stageIndex} `);
    console.log(`_stageStartLevel    : ${_stageStartLevel} `);
    console.log(`_stageEndevel       : ${_stageEndevel} `);



}

const soname = 'libil2cpp.so'


const il2cpp_main = ()=>{

    console.log(soname, JSON.stringify(MyFrida.getELFInfoInModule(soname)))


    // console.log(JSON.stringify(MyFrida.androidAppInfo()))
    Il2Cpp.perform(()=>{
        Il2Cpp.dump('dump.cs');
        console.log(`Unity Version: ${getUnityVersion()}`)

        // il2cpp_hook();
        // dumpAllLevelData();
        // dumpAllLevelData1();

        // listGameObjects(true);
        // dumpCurrentScene(true);

        // listTextures();



    })

}


console.log('##################################################')
Java.perform(il2cpp_main)

