

import 'frida-il2cpp-bridge'
import "ts-frida"

import {
    C,
    dumpCurrentScene,
    dumpScenes,
    findObjects,
    listGameObjects,
    listMeshes,
    listTextures,
} from '../il2cppUtils.js'

const il2cpp_hook = ()=>{
    const Assembly_CSharp = Il2Cpp.domain.assembly('Assembly-CSharp');
    Il2Cpp.trace()
        .assemblies(Assembly_CSharp)
        .filterClasses(c=>!c.name.includes('GuruFramework'))
        .and()
        .attach()
}

const parseHintControllers = (livesController:Il2Cpp.Object) =>{
    
}

const parseLivesControllers = (livesController:Il2Cpp.Object) =>{
}

const parseIPersistentProgressService = (IPersistentProgressService:Il2Cpp.Object)=>{
    const playerProgress = IPersistentProgressService.method('get_Progress').invoke() as Il2Cpp.Object;

    return {
        playerProgress : parsePlayerProgress(playerProgress),
    }

}

const parsePlayerProgress = (playerProgress:Il2Cpp.Object)=>{

    const MaxLevel           = playerProgress.field('MaxLevel'             ). value as number;
    const CurrentLevel       = playerProgress.field('CurrentLevel'         ). value as number;
    const SumScore           = playerProgress.field('SumScore'             ). value as number;
    const BackgroundIndex    = playerProgress.field('BackgroundIndex'      ). value as number;
    const CapIndex           = playerProgress.field('CapIndex'             ). value as number;
    const BallIndex          = playerProgress.field('BallIndex'            ). value as number;
    const ExtraTubes         = playerProgress.field('ExtraTubes'           ). value as number;
    const Sink               = playerProgress.field('Sink'                 ). value as number;
    const Hint               = playerProgress.field('Hint'                 ). value as number;
    const Undo               = playerProgress.field('Undo'                 ). value as number;
    const Moves              = playerProgress.field('Moves'                ). value as number;

    // playerProgress.field('ExtraTubes'           ).value = 999999;
    // playerProgress.field('Sink'                 ).value = 999999;
    // playerProgress.field('Hint'                 ).value = 999999;

    return {
        MaxLevel           ,
        CurrentLevel       ,
        SumScore           ,
        BackgroundIndex    ,
        CapIndex           ,
        BallIndex          ,
        ExtraTubes         ,
        Sink               ,
        Hint               ,
        Undo               ,
        Moves              ,
    }

}

const dumpGameController = ()=>{
    const CodeBase_GameCore_Game_GameController = C('Assembly-CSharp', 'CodeBase.GameCore.Game.GameController'); 

    const GameController = findObjects(CodeBase_GameCore_Game_GameController, true);
    
    console.log(`GameController: ${GameController}`);

    const CurrentLevel = GameController.field('CurrentLevel').value as number;
    console.log(`CurrentLevel: ${CurrentLevel}`);

    console.log(`Lives controller: ${JSON.stringify(parseLivesControllers(GameController.field('livesController').value as Il2Cpp.Object))}`)
    console.log(`Hint controller: ${JSON.stringify(parseHintControllers(GameController.field('hintController').value as Il2Cpp.Object))}`)
    console.log(`Persistent progress service: ${JSON.stringify(parseIPersistentProgressService(GameController.field('progressService').value as Il2Cpp.Object))}`)

}

const il2cpp_main = ()=>{

    console.log(JSON.stringify(MyFrida.androidAppInfo()))

    Il2Cpp.perform(()=>{

        console.log(`Unity version: ${Il2Cpp.unityVersion}`)

        // Il2Cpp.dump('Unity.dump.cs');

        // il2cpp_hook();

        dumpGameController();


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

