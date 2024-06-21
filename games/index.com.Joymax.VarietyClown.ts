

import 'frida-il2cpp-bridge'
import "ts-frida"

import {
    C,
    dumpCurrentScene,
    dumpScenes,
    hookIl2cppClassFuns,
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

const soname='libil2cpp.so'

const instpectPoiniter = (p:NativePointer)=>{
    const m = Process.findModuleByAddress(p)
    console.log(p.toString(), 
        m? m.name : 'null',
        m? (p.sub(m.base)) : 'null',
    )
    
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

    const il2cpp_resolve_icall = new NativeFunction(
        Module.getExportByName(soname, 'il2cpp_resolve_icall'),
        'pointer',
        ['pointer']
    )

    const UnityEngine_AudioClip__GetData                  = il2cpp_resolve_icall(Memory.allocUtf8String( 'UnityEngine.AudioClip::GetData' ) ) ;
    const UnityEngine_AudioClip__SetData                  = il2cpp_resolve_icall(Memory.allocUtf8String( 'UnityEngine.AudioClip::SetData' ) ) ;
    const UnityEngine_AudioClip__Construct_Internal       = il2cpp_resolve_icall(Memory.allocUtf8String( 'UnityEngine.AudioClip::Construct_Internal' ) ) ;
    const UnityEngine_AudioClip__GetName                  = il2cpp_resolve_icall(Memory.allocUtf8String( 'UnityEngine.AudioClip::GetName' ) ) ;
    const UnityEngine_AudioClip__CreateUserSound          = il2cpp_resolve_icall(Memory.allocUtf8String( 'UnityEngine.AudioClip::CreateUserSound' ) ) ;
    const UnityEngine_AudioClip__get_length               = il2cpp_resolve_icall(Memory.allocUtf8String( 'UnityEngine.AudioClip::get_length' ) ) ;
    const UnityEngine_AudioClip__get_samples              = il2cpp_resolve_icall(Memory.allocUtf8String( 'UnityEngine.AudioClip::get_samples' ) ) ;
    const UnityEngine_AudioClip__get_channels             = il2cpp_resolve_icall(Memory.allocUtf8String( 'UnityEngine.AudioClip::get_channels' ) ) ;
    const UnityEngine_AudioClip__get_frequency            = il2cpp_resolve_icall(Memory.allocUtf8String( 'UnityEngine.AudioClip::get_frequency' ) ) ;
    const UnityEngine_AudioClip__get_isReadyToPlay        = il2cpp_resolve_icall(Memory.allocUtf8String( 'UnityEngine.AudioClip::get_isReadyToPlay' ) ) ;
    const UnityEngine_AudioClip__get_loadType             = il2cpp_resolve_icall(Memory.allocUtf8String( 'UnityEngine.AudioClip::get_loadType' ) ) ;
    const UnityEngine_AudioClip__LoadAudioData            = il2cpp_resolve_icall(Memory.allocUtf8String( 'UnityEngine.AudioClip::LoadAudioData' ) ) ;
    const UnityEngine_AudioClip__UnloadAudioData          = il2cpp_resolve_icall(Memory.allocUtf8String( 'UnityEngine.AudioClip::UnloadAudioData' ) ) ;
    const UnityEngine_AudioClip__get_preloadAudioData     = il2cpp_resolve_icall(Memory.allocUtf8String( 'UnityEngine.AudioClip::get_preloadAudioData' ) ) ;
    const UnityEngine_AudioClip__get_ambisonic            = il2cpp_resolve_icall(Memory.allocUtf8String( 'UnityEngine.AudioClip::get_ambisonic' ) ) ;
    const UnityEngine_AudioClip__get_loadInBackground     = il2cpp_resolve_icall(Memory.allocUtf8String( 'UnityEngine.AudioClip::get_loadInBackground' ) ) ;
    const UnityEngine_AudioClip__get_loadState            = il2cpp_resolve_icall(Memory.allocUtf8String( 'UnityEngine.AudioClip::get_loadState' ) ) ;

    console.log(`UnityEngine_AudioClip_get_length: ${UnityEngine_AudioClip__get_length}`)
    instpectPoiniter(UnityEngine_AudioClip__get_length);
    MyFrida.HookAction.addInstance(
        UnityEngine_AudioClip__get_length, 
        new MyFrida.HookFunAction({
            name:'UnityEngine_AudioClip_get_length',
            enterFun(args, tstr, thiz) {

                instpectPoiniter(args[0])
                instpectPoiniter(args[1])
                
            },
        }))

    const method = UnityEngine_AudioClip.method('get_length');
    console.log(`method: ${method.virtualAddress}`)
    instpectPoiniter(method.virtualAddress);
    MyFrida.HookAction.addInstance(
        method.virtualAddress, 
        new MyFrida.HookFunAction({
            name:'get_length',
        }))

    return;


    for(const item of allAudioClips) {
        const audioClip = item as Il2Cpp.Object;
        console.log(audioClip.toString(), audioClip.handle)
        const length = audioClip.method('get_length').invoke() as number;
        console.log(`length: ${length}`)
        const loadAudioDataDone = audioClip.method('LoadAudioData').invoke() as boolean;
        console.log(`loadAudioDataDone: ${loadAudioDataDone}`)

        instpectPoiniter(ptr(0xc1b69784))

        const pfun = UnityEngine_AudioClip__get_channels;
        console.log(`pfun: ${pfun}`)
        instpectPoiniter(pfun);
        MyFrida.runFunWithExceptHandling(()=>{
            const channels = new NativeFunction(
                pfun,
                'int',
                ['pointer'],
            )(audioClip.handle);
            console.log(`channels: ${channels}`)
        })
        break;
    }

    


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

