

import 'frida-il2cpp-bridge'
// import "ts-frida"

import {
    dumpCurrentScene,
    C,
    dumpScenes,
    listGameObjects,
    listMeshes,
    listTextures,
    showIl2cppInstances,
    parseInt32Arrray,
} from '../il2cppUtils.js'

const il2cpp_hook = ()=>{
    const Assembly_CSharp = Il2Cpp.domain.assembly('Assembly-CSharp');
    Il2Cpp.trace()
        .assemblies(Assembly_CSharp)
        //.filterClasses(c=>!c.name.includes('GuruFramework'))
        .and()
        .attach()
}

const dumpProgressManager = ()=>{

    const ProgressManager = C("Assembly-CSharp", "ProgressManager");
    const progressManager = ProgressManager.field('Instance').value as Il2Cpp.Object;
    console.log(`progressManager: ${progressManager}`)

    showIl2cppInstances(progressManager);

}

const dumpGameManager = () =>{

    const GameManager = C("Assembly-CSharp", "GameManager");
    const gameManager = GameManager.field('Instance').value as Il2Cpp.Object;
    console.log(`gameManager: ${gameManager}`)  


    showIl2cppInstances(gameManager);

    const scriptableData = gameManager.field('scriptableData').value as Il2Cpp.Object;
    dumpPersistantData(scriptableData);
}

const dumpPersistantData = (data:Il2Cpp.Object) =>{

    showIl2cppInstances(data);

    data.field('coinAmount').value = 999999;
    data.field('adsEnabled').value = false;

    const completedLevels = (data.field('completedLevels').value as Il2Cpp.Object)
        .method('ToArray').invoke() as Il2Cpp.Array;
    console.log(`completedLevels: ${JSON.stringify(parseInt32Arrray(completedLevels))}`)

    const boughtLevels = data.field('boughtLevels').value as Il2Cpp.Object;
    console.log(`boughtLevels: ${boughtLevels.method('ToArray').invoke()}`)
    // data.field('nextLevel').value = Il2Cpp.string('59')

    if (0) {

        for (let level = 3; level <= 108; level++) {
            const SystemInt32 = C("mscorlib", "System.Int32");
            const systemInt32 = SystemInt32.method('Parse').overload('System.String')
                .invoke(Il2Cpp.string(level.toString())) as Il2Cpp.Object;
            console.log(`systemInt32: ${systemInt32}`)

            console.log(`value: ${boughtLevels.field("_size").value}`)

            boughtLevels.method('Add').invoke(systemInt32);
        }
    }
    //add 
    // (boughtLevels as Il2Cpp.Object).me

    // 
    
}

const dumpIAPManager = ()=>{

    const IAPManager = C("Assembly-CSharp", "IAPManager");
    const iapManager = IAPManager.field('instance').value as Il2Cpp.Object;
    console.log(`iapManager: ${iapManager}`)
    showIl2cppInstances(iapManager);

    iapManager.method('BuyCoin100').invoke();
}

const dumpHintManager = ()=>{
    const HintManager = C("Assembly-CSharp", "HintManager");
    const hintManager = HintManager.field('Instance').value as Il2Cpp.Object;

    console.log(`hintManager: ${hintManager}`)
    showIl2cppInstances(hintManager);

}

const il2cpp_main = ()=>{


    Il2Cpp.perform(()=>{

        console.log(`Unity version: ${Il2Cpp.unityVersion}`)


        // Il2Cpp.dump('Unity.dump.cs');

        // il2cpp_hook();

        // dumpHintManager();

        // dumpProgressManager();

        dumpGameManager();

        // dumpIAPManager();



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

