

import * as path from 'path'
import 'frida-il2cpp-bridge'
import "ts-frida"

import {
    C,
    parseVector2,
    parseVector3,
    parseVector2Array,
    getUnityVersion,
    parseSystem_Collections_Generic_List,
    parseInt32Arrray,
    listTextures,
    listGameObjects,
    dumpCurrentScene,
    getScreenResolution,
    parseTransform,
    parseCamera,
} from '../il2cppUtils.js'

import {
    mod as patchlibinfo,
} from '../modinfos/libmodpatchgame.js'
import { copyFileSync } from 'fs'

const il2cpp_hook = ()=>{
    //const Assembly_CSharp = Il2Cpp.domain.assembly('Assembly-CSharp');
    const Assembly_CSharp = Il2Cpp.domain.assembly('Assembly-CSharp');
    const UnityEngine_UIElementsModule = Il2Cpp.domain.assembly('UnityEngine.UIElementsModule');
    Il2Cpp.trace(true)
        .assemblies(
            Assembly_CSharp,
        //    UnityEngine_UIElementsModule,
        )
        .filterMethods(m=>m.name.includes('ShowTip'))
        .and()
        .attach()
}

const il2cpp_method_hook = () =>{
    const CircleShaderController = C('Assembly-CSharp', 'CircleShaderController');
    const ShowTip = CircleShaderController.method('ShowTip');
    // System.Void ShowTip(UnityEngine.RectTransform rectTipCanvas, LevelDiff diff, System.Boolean showMask, System.Boolean showFinger);
    // ShowTip.implementation = function (
    //     rectTipCanvas:Il2Cpp.Object, 
    //     diff:Il2Cpp.Object, 
    //     showMask:boolean, 
    //     showFinger:boolean
    // ): void  {
    //     // <--- onEnter
    //     this.method<boolean>("ShowTip").invoke(rectTipCanvas,diff,showMask,showFinger);
    //     // <--- onLeave
    // };

}

const il2cpp_method_native_hook = () => {
    const CircleShaderController = C('Assembly-CSharp', 'CircleShaderController');
    const ShowTip = CircleShaderController.method('ShowTip');

    console.log(`Method: ${ShowTip}`)

    const hooks : {p:NativePointer, name:string, opts:MyFrida.HookFunActionOptArgs} [] = [
        {p:ShowTip.virtualAddress, name:'CircleShaderController.ShowTip', opts:{
            nparas:6,

            // System.Void CircleShaderController::ShowTip(UnityEngine.RectTransform rectTipCanvas, LevelDiff diff, System.Boolean showMask, System.Boolean showFinger)

            enterFun(args, tstr, thiz) {

                const pthiz         = new Il2Cpp.Object(args[0]);
                const rectTipCanvas = new Il2Cpp.Object(args[1]);
                const diff          = new Il2Cpp.Object(args[2]);
                const showMask      = args[3].toUInt32();
                const showFinger    = args[4].toUInt32();

                console.log(tstr, `rectTipCanvas: ${rectTipCanvas} diff: ${diff} showMask: ${showMask} showFinger: ${showFinger}`)

                const rect = rectTipCanvas.method('get_rect').invoke() ;
                console.log(tstr, `rect: ${rect}`)

                const Width = diff.field("Width" ).value as number;
                const Height= diff.field("Height").value as number;
                console.log(tstr, `Width: ${Width} Height: ${Height}`)

                const _tipCenter =  pthiz.field('_tipCenter').value as Il2Cpp.Object;
                console.log(tstr, `_tipCenter: ${JSON.stringify(parseTransform(_tipCenter))} _tipCenter: ${_tipCenter}`)

            },

        },},
    ];

    [
        ... hooks,
    ].forEach(({p, name, opts}) => {
        console.log(`hooking ${name} ${JSON.stringify(opts  )}`)
        MyFrida.HookAction.addInstance(p, new MyFrida.HookFunAction({...opts,name}))
    })
}

const parseLevelView = (levelView:Il2Cpp.Object) =>{

    const UnityEngine_Camera = C("UnityEngine.CoreModule",'UnityEngine.Camera');
    const mainCam = UnityEngine_Camera.method('get_current').invoke() as Il2Cpp.Object;
    console.log(`Main Camera: ${mainCam}`);

    const _rectRateDialog    =  levelView.field("_rectRateDialog"     ).value as Il2Cpp.Object;
    const _rectDiffView      =  levelView.field("_rectDiffView"       ).value as Il2Cpp.Object;
    const RectFrame          =  levelView.field("RectFrame"           ).value as Il2Cpp.Object;
    const RectTop            =  levelView.field("RectTop"             ).value as Il2Cpp.Object;
    const RectBottom         =  levelView.field("RectBottom"          ).value as Il2Cpp.Object;
    const RectPictureView    =  levelView.field("RectPictureView"     ).value as Il2Cpp.Object;

    const position = (mainCam
        .method('WorldToScreenPoint').overload("UnityEngine.Vector3")
        .invoke(( RectBottom as Il2Cpp.Object).method('get_position').invoke() as Il2Cpp.Object)
        ) as Il2Cpp.Object ;
    console.log(`position: ${JSON.stringify(parseVector3(position))}`)


    return {

    _rectRateDialog    : parseTransform(_rectRateDialog ) ,
    _rectDiffView      : parseTransform(_rectDiffView   ) ,
    RectFrame          : parseTransform(RectFrame       ) ,
    RectTop            : parseTransform(RectTop         ) ,
    RectBottom         : parseTransform(RectBottom      ) ,
    RectPictureView    : parseTransform(RectPictureView ) ,

    }
}

const parseUserData = (userData:Il2Cpp.Object) =>{

    const _userDataFile                =(userData.field('_userDataFile'                 ).value as Il2Cpp.String).toString();
    const _udid                        =(userData.field('_udid'                         ).value as Il2Cpp.String).toString();
    const _name                        =(userData.field('_name'                         ).value as Il2Cpp.String).toString();
    const _country                     =(userData.field('_country'                      ).value as Il2Cpp.String).toString();
    const _gold                        = userData.field('_gold'                         ).value;
    const _chestBonusFinishLevel       = userData.field('_chestBonusFinishLevel'        ).value;
    const _level                       = userData.field('_level'                        ).value;
    const _specialLevel                = userData.field('_specialLevel'                 ).value;
    const _specialLevelState           = userData.field('_specialLevelState'            ).value;
    const _noAD                        = userData.field('_noAD'                         ).value;
    const _hasBuyProp                  = userData.field('_hasBuyProp'                   ).value;
    const _isNoUseTaskButton           = userData.field('_isNoUseTaskButton'            ).value;
    const _playLevel                   = userData.field('_playLevel'                    ).value;
    const _eventTest                   = userData.field('_eventTest'                    ).value;
    const _isNewOldEventIsTest         = userData.field('_isNewOldEventIsTest'          ).value;
    const _isEventNewOld               = userData.field('_isEventNewOld'                ).value;

    return {
        _userDataFile                ,
        _udid                        ,
        _name                        ,
        _country                     ,
        _gold                        ,
        _chestBonusFinishLevel       ,
        _level                       ,
        _specialLevel                ,
        _specialLevelState           ,
        _noAD                        ,
        _hasBuyProp                  ,
        _isNoUseTaskButton           ,
        _playLevel                   ,
        _eventTest                   ,
        _isNewOldEventIsTest         ,
        _isEventNewOld               ,
    }
}

const parseLevelAsset = (levelAsset:Il2Cpp.Object) =>{

    return {

    ID              : (levelAsset.field('ID'             ).value as Il2Cpp.String).toString(),
    AssetsType      : levelAsset.field('AssetsType'     ).value,
    Level           : levelAsset.field('Level'          ).value,
    StorageABPath   : (levelAsset.field('StorageABPath'  ).value as Il2Cpp.String).toString(),
    LocalABPath     : levelAsset.field('LocalABPath'    ).value,
    _generationCode : levelAsset.field('_generationCode').value,
    }
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

const parseCircleShaderController = (circleShaderController:Il2Cpp.Object)=>{
    const _shrinkNum = circleShaderController.field('_shrinkNum').value as number;
    const Slider = circleShaderController.field('Slider').value as number;
    const Center = circleShaderController.field('Center').value as number;

    return {
        _shrinkNum,
        Slider,
        Center,
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

    const LevelManager = C("Assembly-CSharp",'LevelManager');

    const levelManager = LevelManager.method('get_Instance').invoke() as Il2Cpp.Object;

    console.log(`Level Manager: ${levelManager}`)

    console.log(`_DiffNum: ${levelManager.field('_DiffNum').value as number}`)
    console.log(`GameCurrentTime: ${levelManager.field('GameCurrentTime').value as number}`)
    console.log(`_GameFindDiffNum: ${levelManager.field('_GameFindDiffNum').value as number}`)
    console.log(`_levelLife: ${levelManager.field('_levelLife').value as number}`)

    console.log(`Level Type: ${levelManager.method('get_LevelType').invoke()}`)
    console.log(`Level ID: ${levelManager.method('get_LevelID').invoke()}`)
    console.log(`Level Name: ${levelManager.method('get_LevelName').invoke()}`)
    console.log(`Level Category: ${levelManager.method('get_LevelCategory').invoke()}`)
    console.log(`Level : ${levelManager.method('get_Level').invoke()}`)
    console.log(`Level cost time: ${levelManager.method('get_LevelCostTime').invoke()}`)
    console.log(`Actually game time: ${levelManager.method('get_ActuallyGameTime').invoke()}`)

    console.log(`Level asset: ${JSON.stringify(parseLevelAsset(levelManager.field('LevelAsset').value as Il2Cpp.Object))}`)


    const levelData = levelManager.method('get_LevelData').invoke() as Il2Cpp.Object;
    console.log(`Level Data: ${JSON.stringify(parseLevelData(levelData))}`)

    for(let n=0; n< 5;n++){

        console.log(`Position${n}: ${levelManager.method('GetDiffPos').invoke(n)}`)
        console.log(`Position${n}: ${levelManager.method('GetDiffFramePos').invoke(n)}`)
    }

    const levelView = levelManager.field('View').value as Il2Cpp.Object;
    const _topTipMaskCtl = parseCircleShaderController(levelView.field('_topTipMaskCtl').value as Il2Cpp.Object);
    const _bottomTipMaskCtl = parseCircleShaderController(levelView.field('_bottomTipMaskCtl').value as Il2Cpp.Object);

    console.log(`_topTipMaskCtl: ${JSON.stringify(_topTipMaskCtl)}`)
    console.log(`_bottomTipMaskCtl: ${JSON.stringify(_bottomTipMaskCtl)}`)

    console.log(`Level View: ${JSON.stringify(parseLevelView(levelView))}`)




}

const dumpUserInfoMangaer = ()=>{
    const UserInfoManager = Il2Cpp.domain.assembly("Assembly-CSharp").image
        .class("UserInfoManager");

    console.log(`Level: ${UserInfoManager.method('get_level').invoke()}`)
    console.log(`Chest finish level: ${UserInfoManager.method('get_chest_finish_level').invoke()}`)

    const userInfoManager = UserInfoManager.method("get_Instance").invoke() as Il2Cpp.Object;

    console.log(`Gold: ${userInfoManager.method("get_Gold").invoke()}`)
    console.log(`Level: ${userInfoManager.method("get_Level").invoke()}`)
    console.log(`Special level: ${userInfoManager.method("get_SpecialLevel").invoke()}`)
    console.log(`Is no use task button: ${userInfoManager.method("get_IsNoUseTaskButton").invoke()}`)

    const userData = userInfoManager.method('get_Data').invoke() as Il2Cpp.Object;
    console.log(`Userdata: ${JSON.stringify(parseUserData(userData))}`)

    userData.field('_gold').value = 9999999;
    userData.field('_noAD').value = true;
    userData.field('_hasBuyProp').value = true;
    // set Gold
    const gold = userData.method('get_Gold').invoke() as number;
    console.log('gold', gold)

    //userData.method('set_Gold') .invoke(100) 

}

const dumpApplication = ()=> {

    const UnityEngine_Application = Il2Cpp.domain.assembly('UnityEngine.CoreModule').image
        .class('UnityEngine.Application');

    const platform = UnityEngine_Application.method('get_platform').invoke();
    console.log(`Platform: ${platform} ${typeof platform} ${JSON.stringify(platform)}  `);


}
const testRay = () => {

    const UnityEngine_Camera = C('UnityEngine.CoreModule', "UnityEngine.Camera");
    const cam = UnityEngine_Camera.method('get_current').invoke() as Il2Cpp.Object;
    const Vector3 = C("UnityEngine.CoreModule", 'UnityEngine.Vector3');
    const Vector2 = C("UnityEngine.CoreModule", 'UnityEngine.Vector2');
    const screenPointer = Vector3.method('get_zero').invoke() as Il2Cpp.Object;
    screenPointer.field('x').value = 1200;
    screenPointer.field('y').value = 500;
    screenPointer.field('z').value = 20.;


    console.log(`screenPointer: ${JSON.stringify(parseVector3(screenPointer))}`)

    const ScreenPointToRay = cam.method('ScreenPointToRay').overload('UnityEngine.Vector3');
    console.log(`ScreenPointToRay: ${ScreenPointToRay}`)

    const ray = ScreenPointToRay.invoke(screenPointer) as Il2Cpp.Object;
    console.log(`ray: ${ray}`)

    const m_Origin = ray.field('m_Origin').value as Il2Cpp.Object;
    const m_Direction = ray.field('m_Direction').value as Il2Cpp.Object;

    const origin = Vector2.method('get_zero').invoke() as Il2Cpp.Object;
    const direction = Vector2.method('get_zero').invoke() as Il2Cpp.Object;

    console.log(`origin: ${JSON.stringify(m_Origin)}`)
    console.log(`direction: ${JSON.stringify(m_Direction)}`)

    origin.field('x').value = m_Origin.field('x').value as number;
    origin.field('y').value = m_Origin.field('y').value as number;

    direction.field('x').value = m_Direction.field('x').value as number;
    direction.field('y').value = m_Direction.field('y').value as number;

    const UnityEngine_Physcics2D = C('UnityEngine.Physics2DModule', "UnityEngine.Physics2D");

    const hit = UnityEngine_Physcics2D.method('Raycast').overload('UnityEngine.Vector2', 'UnityEngine.Vector2').invoke(origin, direction) as Il2Cpp.Object;

    console.log(`raycast: ${hit} ${JSON.stringify(hit)}`);
    const collider = hit.method('get_collider').invoke() as Il2Cpp.Object;
    console.log(`collider: ${collider} ${JSON.stringify(collider)} ${collider != null}`);

    if (!collider.isNull()) {

        const selectedObject = collider.method('get_gameObject').invoke() as Il2Cpp.Object;
        console.log(`selectedObject: ${selectedObject}`)

    }

}

const findAllDiffGameObjects = (patchlib: MyFrida.PATHLIB_INFO_TYPE) => {
    const gameObjects = listGameObjects(true).allGameObjects;
    for (const go of gameObjects) {

        const x = go.transform.screen_position.x;
        const y = go.transform.screen_position.y;
        const name = go.name;


        const regex = /"Diff[0-9]"/;

        console.log(`${x} ${y} ${name} ${regex.test(name)}`)

        if (regex.test(name)) {

            console.log(`Diff :${name}`)

            const pfun = patchlib.symbols.addDiff;

            if (pfun) {
                new NativeFunction(pfun, 'void', ['int', 'int'])(
                    Math.floor(x),
                    Math.floor(y),
                );
            }
        }




    }

}


const soname = 'libil2cpp.so'

    const _frida_log_callback = new NativeCallback(
    function (sp) {
        const message = sp.readUtf8String();
        console.log(message);
        globalThis.console.log(message);
    }, 
    // Return type of the callback function.
    'void', 
    // Argument types of the callback function.
    ['pointer']);

const il2cpp_main = ()=>{

    const patchlib  = patchlibinfo.load(
        path.join('/data/local/tmp','libpatchgame.so'),
        [
            soname,
        ],
        {
            ... MyFrida.frida_symtab,

        }
    )

    const appInfo = MyFrida.androidAppInfo();
    console.log(JSON.stringify(appInfo))

    const dumpDir = `${appInfo.externalFilesDir}/dumps/`

    console.log(soname, JSON.stringify(MyFrida.getELFInfoInModule(soname)))
    const m = Process.getModuleByName(soname);
    console.log(m.path)

    // console.log(JSON.stringify(MyFrida.androidAppInfo()))
    Il2Cpp.perform(()=>{
        const { width, height } = getScreenResolution();
        console.log(`Screen resolution: ${width}x${height}`)


        if (patchlib.symbols.init!=undefined) {
            new NativeFunction(patchlib.symbols.init,'int',['int','int'])(width, height);
        }

        // hook 
        const hook_game = ()=>{

            const hooksForEGL : {p:NativePointer, name:string, opts:MyFrida.HookFunActionOptArgs} [] = [
                {p:Module.getExportByName("libGLES_mali.so",'eglSwapBuffers'), name: 'eglSwapBuffers', opts:{
                    hide:true,
                    enterFun(args, tstr, thiz) {
                        if (patchlib.symbols.hookGL!=undefined) {
                            new NativeFunction(patchlib.symbols.hookGL,'int',['int','int'])(width, height);
                        }
                    },
                }},
            ];

            const hooksForInputEvent : {p:NativePointer, name:string, opts:MyFrida.HookFunActionOptArgs} [] = [
                {p:Module.getExportByName("libandroid.so",'_ZN7android32android_view_KeyEvent_fromNativeEP7_JNIEnvPKNS_8KeyEventE'), name: 'android::android_view_KeyEvent_fromNative', opts:{ 

                    hide:true,

                    enterFun(args, tstr, thiz) {
                        if(patchlib.symbols.processInputEvent){
                            new NativeFunction(patchlib.symbols.processInputEvent,'void',['pointer'])(
                                args[1]
                            );
                        }
                        
                        
                    },

                }, },

            ];

            [
                ... hooksForEGL,
                ... hooksForInputEvent,
            ].forEach(({p, name, opts})=>{
                console.log(`hook ${name} ${JSON.stringify(opts)}`)
                MyFrida.HookAction.addInstance(p, new MyFrida.HookFunAction({...opts, name}));
            })
        }

        hook_game();

        // Il2Cpp.dump('Unity.dump.cs');

        console.log(`Unity Version: ${getUnityVersion()}`)

        // il2cpp_hook();

        findAllDiffGameObjects(patchlib);
        
        // il2cpp_method_hook();

        // il2cpp_method_native_hook();

        //console.log(`All game objects: ${JSON.stringify(listGameObjects())}`)


        // dumpCurrentScene(true);

        // listTextures(dumpDir);

        // dumpMainLevelManager();

        // dumpLevelManager();

        // dumpUserInfoMangaer();

        // dumpApplication();

        // parseCamera();


    })

}


console.log('##################################################')
Java.perform(il2cpp_main)

