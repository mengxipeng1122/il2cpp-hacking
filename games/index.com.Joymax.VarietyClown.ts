

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

const inspectPointer = (p:NativePointer)=>{
    const m = Process.findModuleByAddress(p)
    console.log(p.toString(), 
        m? m.name : 'null',
        m? (p.sub(m.base)) : 'null',
        m? (p.sub(m.base).add(0x10000)) : 'null',
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
    inspectPointer(UnityEngine_AudioClip__get_length);
    MyFrida.HookAction.addInstance(
        UnityEngine_AudioClip__get_length, 
        new MyFrida.HookFunAction({
            name:'UnityEngine_AudioClip_get_length',
            enterFun(args, tstr, thiz) {

                inspectPointer(args[0])
                inspectPointer(args[1])
                
            },
        }))

    const method = UnityEngine_AudioClip.method('get_length');
    console.log(`method: ${method.virtualAddress}`)
    inspectPointer(method.virtualAddress);
    MyFrida.HookAction.addInstance(
        method.virtualAddress, 
        new MyFrida.HookFunAction({
            name:'get_length',
        }))


    for(const item of allAudioClips) {
        const audioClip = item as Il2Cpp.Object;
        console.log(audioClip.toString(), audioClip.handle)
        const length = audioClip.method('get_length').invoke() as number;
        console.log(`length: ${length}`)
        const loadAudioDataDone = audioClip.method('LoadAudioData').invoke() as boolean;
        console.log(`loadAudioDataDone: ${loadAudioDataDone}`)

        inspectPointer(ptr(0xc1b69784))

        const pfun = UnityEngine_AudioClip__get_channels;
        console.log(`pfun: ${pfun}`)
        inspectPointer(pfun);
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

const test_buf = Memory.alloc(Process.pageSize)

const dumpAudioClips = ()=>{
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
    );
    const il2cpp_object_unbox = new NativeFunction(
        Module.getExportByName(soname, 'il2cpp_object_unbox'),
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

    console.log('UnityEngine_AudioClip__GetData                  ', UnityEngine_AudioClip__GetData                      );
    console.log('UnityEngine_AudioClip__SetData                  ', UnityEngine_AudioClip__SetData                      );
    console.log('UnityEngine_AudioClip__Construct_Internal       ', UnityEngine_AudioClip__Construct_Internal           );
    console.log('UnityEngine_AudioClip__GetName                  ', UnityEngine_AudioClip__GetName                      );
    console.log('UnityEngine_AudioClip__CreateUserSound          ', UnityEngine_AudioClip__CreateUserSound              );
    console.log('UnityEngine_AudioClip__get_length               ', UnityEngine_AudioClip__get_length                   );
    console.log('UnityEngine_AudioClip__get_samples              ', UnityEngine_AudioClip__get_samples                  );
    console.log('UnityEngine_AudioClip__get_channels             ', UnityEngine_AudioClip__get_channels                 );
    console.log('UnityEngine_AudioClip__get_frequency            ', UnityEngine_AudioClip__get_frequency                );
    console.log('UnityEngine_AudioClip__get_isReadyToPlay        ', UnityEngine_AudioClip__get_isReadyToPlay            );
    console.log('UnityEngine_AudioClip__get_loadType             ', UnityEngine_AudioClip__get_loadType                 );
    console.log('UnityEngine_AudioClip__LoadAudioData            ', UnityEngine_AudioClip__LoadAudioData                );
    console.log('UnityEngine_AudioClip__UnloadAudioData          ', UnityEngine_AudioClip__UnloadAudioData              );
    console.log('UnityEngine_AudioClip__get_preloadAudioData     ', UnityEngine_AudioClip__get_preloadAudioData         );
    console.log('UnityEngine_AudioClip__get_ambisonic            ', UnityEngine_AudioClip__get_ambisonic                );
    console.log('UnityEngine_AudioClip__get_loadInBackground     ', UnityEngine_AudioClip__get_loadInBackground         );
    console.log('UnityEngine_AudioClip__get_loadState            ', UnityEngine_AudioClip__get_loadState                );

    const soundHandleAPI_GetLengthMS = Process.getModuleByName("libunity.so").base.add(0x003c3ed1).sub(0x10000);
    const DSPI_validate =  new NativeFunction(
        Process.getModuleByName("libunity.so").base.add(0x005af70f).sub(0x10000),
        'int',
        ['pointer','pointer'],
    );

    const hooks : {p:NativePointer, name: string , opts:MyFrida.HookFunActionOptArgs} [] = [

        // {p:UnityEngine_AudioClip__get_length,  name:'UnityEngine_AudioClip__get_length', opts:{
        //     enterFun(args, tstr, thiz) {
        //         const audioClipObj = args[0];
        //         const audioClip = il2cpp_object_unbox(audioClipObj).readPointer();
        //         MyFrida.dumpMemory(audioClip, 0x40);
        //         const length = audioClip.add(0x30).readFloat();
        //         console.log(`length: ${length}`);
        //     },
        // }},

        // {p:Process.getModuleByName("libunity.so").base.add(0x003bb299).sub(0x10000),  name:'AudioClip::GetSampleCountEx', opts:{
        //     enterFun(args, tstr, thiz) {
        //     },
        // }},

        {p:soundHandleAPI_GetLengthMS,  name:'SoundHandleAPI::GetLengthMS()', opts:{ }},

    ];

    [
        ... hooks,
    ].forEach((item:{p:NativePointer, name:string, opts:MyFrida.HookFunActionOptArgs})=>{

        console.log(`hooking ${JSON.stringify(item)}`)

        const {p,name, opts} = item;
        inspectPointer(p);
        MyFrida.HookAction.addInstance(p, new MyFrida.HookFunAction({
            ...opts, name,  
        }));
    });

    for(const item of allAudioClips) {
        const audioClipObj = item as Il2Cpp.Object;
        console.log(audioClipObj.toString(), audioClipObj.handle)
        const audioClip = il2cpp_object_unbox(audioClipObj).readPointer();
        const vtab_audioClip = audioClip.readPointer();
        console.log(`vtab_audioClip: ${vtab_audioClip}`)
        inspectPointer(vtab_audioClip);
        MyFrida.dumpMemory(audioClip,0x40);
        const length = audioClipObj.method('get_length').invoke() as number;
        console.log(`length: ${length}`)
        console.log(`   frequency       : ${audioClip.add(0x20).readU32()   }`)
        console.log(`   channel count   : ${audioClip.add(0x24).readU32()   }`)
        console.log(`   Bit per sample  : ${audioClip.add(0x28).readU32()   }`)
        console.log(`   length sec      : ${audioClip.add(0x30).readFloat() }`)

        const soundHandleAPI  = audioClip.add(0x38).readPointer().add(0x0c).readPointer()
        console.log(`   soundHandleAPI  : ${soundHandleAPI}`)
        MyFrida.dumpMemory(soundHandleAPI,0x40);

        const lengthMS =  new NativeFunction(
            soundHandleAPI_GetLengthMS, 'float',['pointer']
        ) (soundHandleAPI);

        console.log(`   lengthMS        : ${lengthMS}`)

        const FMOD__Sound = soundHandleAPI.add(0x3c).readPointer();
        console.log(`   FMOD__Sound     : ${FMOD__Sound}`)
        MyFrida.dumpMemory(FMOD__Sound,0x40);

        const pDSPI =  test_buf.add(0);
        const done = DSPI_validate(FMOD__Sound, pDSPI);
        const DSPI = pDSPI.readPointer();
        console.log(` DSPI_validate: ${done}, ${DSPI} ${DSPI.add(0x11c).readU32()}`)
        MyFrida.dumpMemory(DSPI,0x40)

        // FMOD_RESULT F_API lock                   (unsigned int offset, unsigned int length, void **ptr1, void **ptr2, unsigned int *len1, u      nsigned int *len2);

        const pfun_FMOD_Sound_lock =  DSPI.readPointer().add(0x1c).readPointer();
        console.log(`pfun_FMOD_Sound_lock: ${pfun_FMOD_Sound_lock}`)
        inspectPointer(pfun_FMOD_Sound_lock);
        const FMOD_Sound_lock = new NativeFunction(
            pfun_FMOD_Sound_lock,
            'int',
            ['pointer', 'int', 'int', 'pointer', 'pointer', 'pointer', 'pointer'],
        )
        // FMOD_RESULT F_API unlock                 (void *ptr1, void *ptr2, unsigned int len1, unsigned int len2);                             206 
        const pfun_FMOD_Sound_unlock = DSPI.readPointer().add(0x20).readPointer();
        console.log(`pfun_FMOD_Sound_unlock: ${pfun_FMOD_Sound_unlock}`)
        inspectPointer(pfun_FMOD_Sound_unlock);
        const FMOD_Sound_unlock = new NativeFunction(
            pfun_FMOD_Sound_unlock,
            'int',
            ['pointer', 'pointer', 'pointer', 'int', 'int'],
        )

        const pfun_FMOD_Sound_ReadData = DSPI.readPointer().add(0x78).readPointer();
        console.log(`pfun_FMOD_Sound_ReadData: ${pfun_FMOD_Sound_ReadData}`)
        inspectPointer(pfun_FMOD_Sound_ReadData);
        const FMOD_Sound_ReadData = new NativeFunction(
            pfun_FMOD_Sound_ReadData,
            'int',
            ['pointer', 'pointer', 'int', 'pointer'],
        )

        const pread = test_buf.add(0x10);
        const pptr1 = test_buf.add(0x30)
        const pptr2 = test_buf.add(0x30)
        const plen1 = test_buf.add(0x40)
        const plen2 = test_buf.add(0x50)
        const buf = test_buf.add(0x80)

        // DSP
        const p = DSPI.add(0x44).readPointer().add(0x110);
        console.log(p.toString(), p.readU32())

        let fmod_result = FMOD_Sound_lock(DSPI, 0, 0x100, pptr1, pptr2, plen1, plen2);
        console.log(`lock: ${fmod_result}`)
        //pread.writeU32(0);
        const ptr1 = pptr1.readPointer();
        const len1 = plen1.readU32();
        console.log(`ptr1: ${ptr1}, ${len1}`)
        const ptr2 = pptr2.readPointer();
        const len2 = plen2.readU32();
        console.log(`ptr2: ${ptr2}, ${len2}`)
        fmod_result = FMOD_Sound_ReadData(DSPI, buf, 0x100, pread);
        console.log(`readData: ${fmod_result}`)
        const read = pread.readU32();
        console.log(`read: ${read}`)
        fmod_result = FMOD_Sound_unlock(DSPI,ptr1, ptr2, len1, len2);
        console.log(`unlock: ${fmod_result}`)
        MyFrida.dumpMemory(buf,0x50);

        


        break;
    }

    MyFrida.dumpMemory(test_buf);
}

const native_hook_il2cpp = ()=>{
    const hooks : {p:NativePointer, name: string , opts:MyFrida.HookFunActionOptArgs} [] = [

        {p:Process.getModuleByName("libunity.so").base.add(0x003bac61).sub(0x10000),  name:'AudioClip::InitSteam', opts:{ },},

        {p:Process.getModuleByName("libunity.so").base.add(0x003babbd).sub(0x10000),  name:'AudioClip_ctor', opts:{ },},


        // {p:UnityEngine_AudioClip__get_length,  name:'UnityEngine_AudioClip__get_length', opts:{
        //     enterFun(args, tstr, thiz) {
        //         const audioClipObj = args[0];
        //         const audioClip = il2cpp_object_unbox(audioClipObj).readPointer();
        //         MyFrida.dumpMemory(audioClip, 0x40);
        //         const length = audioClip.add(0x30).readFloat();
        //         console.log(`length: ${length}`);
        //     },
        // }},

        // {p:Process.getModuleByName("libunity.so").base.add(0x003bb299).sub(0x10000),  name:'AudioClip::GetSampleCountEx', opts:{
        //     enterFun(args, tstr, thiz) {
        //     },
        // }},


    ];

    [
        ... hooks,
    ].forEach((item:{p:NativePointer, name:string, opts:MyFrida.HookFunActionOptArgs})=>{

        console.log(`hooking ${JSON.stringify(item)}`)

        const {p,name, opts} = item;
        inspectPointer(p);
        MyFrida.HookAction.addInstance(p, new MyFrida.HookFunAction({
            ...opts, name,  
        }));
    });

}

const il2cpp_main = ()=>{


    Il2Cpp.perform(()=>{

        console.log(`Unity version: ${Il2Cpp.unityVersion}`)

        // Il2Cpp.dump('Unity.dump.cs');

        // il2cpp_hook();

        // native_hook_il2cpp();

        // dumpResources();

        // dumpAudioClips();

        // console.log(`dump scenes: ${JSON.stringify(dumpScenes())}`)

        // console.log(`Game Objects: ${JSON.stringify(listGameObjects())}`)
        // console.log(`Current scene: ${JSON.stringify(dumpCurrentScene(true))}`)
        // dumpCurrentScene(true);

        // listTextures();
        // listMeshes();

    })

}

const main = ()=>{

    MyFrida.hookDlopen('libunity.so', ()=>{

        native_hook_il2cpp();
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

//if(Java.available) Java.perform(il2cpp_main)
//else il2cpp_main()

main();

