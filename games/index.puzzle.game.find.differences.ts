

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
    parseGameObject,
    hookIl2cppClassFuns,
} from '../il2cppUtils.js'

import {
    AKEY_EVENT_A,
    AKEY_EVENT_ACTION_DOWN,
    AKEY_EVENT_B,

} from '../AndroidUtils.js'

import {
    mod as patchlibinfo,
} from '../modinfos/libmodpatchgame.js'

const il2cpp_hook = ()=>{
    //const Assembly_CSharp = Il2Cpp.domain.assembly('Assembly-CSharp');
    const Assembly_CSharp = Il2Cpp.domain.assembly('Assembly-CSharp');
    const UnityEngine_UIElementsModule = Il2Cpp.domain.assembly('UnityEngine.UIElementsModule');
    const DownLoadTask = C("Assembly-CSharp", "DownLoadTask");
    Il2Cpp.trace(true)
        // .assemblies(
        //     Assembly_CSharp,
        // //    UnityEngine_UIElementsModule,
        // )
        // .filterMethods(m=>m.name.includes('ShowTip'))
        .classes(DownLoadTask)
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

    const IsShowing = levelView.field('IsShowing').value as boolean;
    console.log(`position: ${JSON.stringify(parseVector3(position))}`)

    const _isActived = levelView.field('_isActived').value as boolean;


    return {

    _rectRateDialog    : parseTransform(_rectRateDialog ) ,
    _rectDiffView      : parseTransform(_rectDiffView   ) ,
    RectFrame          : parseTransform(RectFrame       ) ,
    RectTop            : parseTransform(RectTop         ) ,
    RectBottom         : parseTransform(RectBottom      ) ,
    RectPictureView    : parseTransform(RectPictureView ) ,

    IsShowing,

    _isActived, 

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

    // console.log(`Level Type: ${levelManager.method('get_LevelType').invoke()}`)
    // console.log(`Level ID: ${levelManager.method('get_LevelID').invoke()}`)
    // console.log(`Level Name: ${levelManager.method('get_LevelName').invoke()}`)
    // console.log(`Level Category: ${levelManager.method('get_LevelCategory').invoke()}`)
    // console.log(`Level : ${levelManager.method('get_Level').invoke()}`)
    // console.log(`Level cost time: ${levelManager.method('get_LevelCostTime').invoke()}`)
    // console.log(`Actually game time: ${levelManager.method('get_ActuallyGameTime').invoke()}`)

    // console.log(`Level asset: ${JSON.stringify(parseLevelAsset(levelManager.field('LevelAsset').value as Il2Cpp.Object))}`)


    // const levelData = levelManager.method('get_LevelData').invoke() as Il2Cpp.Object;
    // console.log(`Level Data: ${JSON.stringify(parseLevelData(levelData))}`)

    // for(let n=0; n< 5;n++){

    //     console.log(`Position${n}: ${levelManager.method('GetDiffPos').invoke(n)}`)
    //     console.log(`Position${n}: ${levelManager.method('GetDiffFramePos').invoke(n)}`)
    // }

     const levelView = levelManager.field('View').value as Il2Cpp.Object;
     if(levelView!=null && !levelView.isNull()){
        console.log(`LevelView: ${levelView}`)
        console.log(`Level View: ${JSON.stringify(parseLevelView(levelView))}`)

     }
    // const _topTipMaskCtl = parseCircleShaderController(levelView.field('_topTipMaskCtl').value as Il2Cpp.Object);
    // const _bottomTipMaskCtl = parseCircleShaderController(levelView.field('_bottomTipMaskCtl').value as Il2Cpp.Object);

    // console.log(`_topTipMaskCtl: ${JSON.stringify(_topTipMaskCtl)}`)
    // console.log(`_bottomTipMaskCtl: ${JSON.stringify(_bottomTipMaskCtl)}`)


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

const findAllDiffGameObjects = () : any[] => {
    const foundGameObjects : any [] = [];

    const gameObjects = listGameObjects(true).allGameObjects;
    for (const go of gameObjects) {

        const x = go.transform.screen_position.x;
        const y = go.transform.screen_position.y;
        const name = go.name;


        const regex = /"Diff\d{1,2}"/;

        // console.log(`${x} ${y} ${name} ${regex.test(name)}`)

        if (regex.test(name)) {

            foundGameObjects.push(go);

            console.log(`Diff :${name}`)

        }

    }

    return foundGameObjects;

}

const listAllLevels = ()=>{
    const MainLevelManager = C("Assembly-CSharp",'MainLevelManager');
    const mainLevelManager = MainLevelManager.method('get_Instance').invoke() as Il2Cpp.Object;
    const maxLevel = mainLevelManager.method("get_MaxLevel").invoke() as number;
    console.log(`Max level: ${maxLevel}`)

    for(let n=0; n <maxLevel; n++) {
        try {
            const levelID = (mainLevelManager.method("GetLevelID").invoke(n + 1) as Il2Cpp.String).content;
            if (levelID) {
                if (levelID.includes('fyx')) {
                    //const url = https://cdn3-dof.fungame.cloud/PicAssets/Android/10_fyx_230526_6_advertise?generation=1685621927374037&alt=media
                    const url = `https://cdn3-dof.fungame.cloud/PicAssets/Android/${levelID}_advertise`;
                    console.log(`${n}: ${levelID} ${url} `)
                }
            }
        }
        catch (e) {
            console.warn(`can not get level of ${n + 1} : ${e}`)
        }


    }

}


const soname = 'libil2cpp.so'

interface global {
    toggleShow: () => void;
    updateDifferences: (mode:number) => void;
}

const il2cpp_main_cheat_android = ()=>{

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

        const toggleShow = () => {
            const pfun = patchlib.symbols.toggleShow;
            if (pfun) {
                new NativeFunction(pfun, 'void', [])();
            }
        }

        const updateDifferences = (mode: number = 0) => {
            {
                const pfun = patchlib.symbols.clearDiffs;
                if (pfun) {
                    new NativeFunction(pfun, 'void', [])();
                }
            }

            const LevelManager = C("Assembly-CSharp", 'LevelManager');
            const levelManager = LevelManager.method('get_Instance').invoke() as Il2Cpp.Object;
            if (levelManager != null && !levelManager.isNull()) {
                const levelView = levelManager.field('View').value as Il2Cpp.Object;
                if (levelView != null && !levelView.isNull()) {
                    const _isActived = levelView.field('_isActived').value as boolean;
                    if (_isActived) {
                        const UnityEngine_GameObject = C("UnityEngine.CoreModule", 'UnityEngine.GameObject');
                        const levelData = levelManager.method('get_LevelData').invoke() as Il2Cpp.Object;
                        const DiffCount = levelData.field('DiffCount').value as number;

                        const findDiffs = (cb:(x:number, y:number)=>void)=> {
                            const allGameObjectsArray = UnityEngine_GameObject
                                .method('FindObjectsOfType')
                                .invoke(UnityEngine_GameObject.type.object) as  Il2Cpp.Array;
                            for(const item of allGameObjectsArray){
                                const go = item as Il2Cpp.Object; 
                                const name = (go.method('get_name').invoke() as Il2Cpp.String).content;
                                const obj = parseGameObject(go);
                                if(name){
                                    const regex = /Diff\d{1,2}/;
                                    if(regex.test(name)) {
                                        console.log(`${name}: ${go.toString()}`)
                                        const {x,y} = obj.transform.screen_position;
                                        cb(x,y);
                                    }
                                }
                            }
                        };

                        const findDiffs0 = (cb: (x: number, y: number) => void) => {
                            for (let i = 1; i <= DiffCount; i++) {
                                const name = `Diff${i}`;
                                const gameObjectName = Il2Cpp.string(name);
                                const go = (UnityEngine_GameObject.method("Find")
                                    .overload('System.String')
                                    .invoke(gameObjectName)) as Il2Cpp.Object;
                                const obj = parseGameObject(go);
                                if (go) {

                                    const x = obj.transform.screen_position.x;
                                    const y = obj.transform.screen_position.y;

                                    cb(x, y);

                                }
                            }

                        };

                        const addDiff = (x: number, y: number) => {
                            if (1) {
                                const pfun = patchlib.symbols.addDiff;
                                if (pfun) {
                                    new NativeFunction(pfun, 'void', ['int', 'int'])(
                                        Math.floor(x),
                                        Math.floor(y),
                                    );
                                }
                            }
                        };


                        switch (mode) {
                            case 0:
                                findDiffs0(addDiff);
                                break;
                            case 1:
                                findDiffs(addDiff);
                                break;
                            default:
                                throw new Error(`unknown mode ${mode}`);
                                break;
                        }

                        {
                            const pfun = patchlib.symbols.getNumOfDiffs;
                            if(pfun) {
                                const cnt = new NativeFunction(pfun,'uint',[])();
                                const msg = `Updated ${cnt} differences`;
                                console.log(msg);
                                MyFrida.showAndroidToast(msg);
                            }
                        }

                        return;

                    }
                }
            }

            {
                const msg = `levelView is not activing `
                console.log(msg);
                MyFrida.showAndroidToast(msg);
            }
            return; 
        }


        if (patchlib.symbols.init!=undefined) {
            new NativeFunction(patchlib.symbols.init,'int',['int','int'])(width, height);
        }

        // hook 
        const hook_game = ()=>{

            let libraryNames = ['libGLES_mail', 'libGLESv3.so', /* Other library names... */];
            let eglSwapBuffers: NativePointer | null = null;

            for (let library of libraryNames) {
                eglSwapBuffers = Module.findExportByName(library, 'eglSwapBuffers');
                if (eglSwapBuffers) break;
            }

            if (!eglSwapBuffers) throw new Error('Cannot find function eglSwapBuffers');

            const hooksForEGL : {p:NativePointer, name:string, opts:MyFrida.HookFunActionOptArgs} [] = [
                {p:eglSwapBuffers, name: 'eglSwapBuffers', opts:{
                    hide:true,
                    enterFun(args, tstr, thiz) {
                        if (patchlib.symbols.hookGL!=undefined) {
                            new NativeFunction(patchlib.symbols.hookGL,'int',['int','int'])(width, height);
                        }
                    },
                }},
            ];

            const AKeyEvent_getAction = new NativeFunction(
                Module.getExportByName('libandroid.so','AKeyEvent_getAction'),'uint',['pointer']);
            const AKeyEvent_getKeyCode= new NativeFunction(
                Module.getExportByName('libandroid.so','AKeyEvent_getKeyCode'),'uint',['pointer']);
            const hooksForInputEvent : {p:NativePointer, name:string, opts:MyFrida.HookFunActionOptArgs} [] = [
                {p:Module.getExportByName("libandroid.so",'_ZN7android32android_view_KeyEvent_fromNativeEP7_JNIEnvPKNS_8KeyEventE'), name: 'android::android_view_KeyEvent_fromNative', opts:{ 

                    hide:true,

                    enterFun(args, tstr, thiz) {
                        const event=args[1];
                        if(!event.isNull()){
                            const action = AKeyEvent_getAction(event);
                            const keyCode = AKeyEvent_getKeyCode(event);
                            console.log(`${keyCode} ${action}`)
                            const keyDown = action == AKEY_EVENT_ACTION_DOWN;
                            if(keyDown){
                                switch(keyCode){
                                    case AKEY_EVENT_A: {
                                        // toggle show
                                        toggleShow();
                                    }
                                    break;

                                    case AKEY_EVENT_B: {
                                        // update diff list
                                        updateDifferences ();
                                    }
                                    break;
                                }

                            }
                        }

                        // if(patchlib.symbols.processInputEvent){
                        //     new NativeFunction(patchlib.symbols.processInputEvent,'void',['pointer'])(
                        //         args[1]
                        //     );
                        // }
                        
                        
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

        // il2cpp_hook();

        // Il2Cpp.dump('Unity.dump.cs');

        console.log(`Unity Version: ${getUnityVersion()}`)

        updateDifferences ();

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

        (globalThis as any).updateDifferences = updateDifferences;
        (globalThis as any).toggleShow        = toggleShow;


    })
}

const il2cpp_main = ()=>{

    // Il2Cpp.perform(()=>{

    //     // Il2Cpp.dump('Unity.dump.cs');

    //     // console.log(`Il2cpp Version: ${Il2Cpp.unityVersion}`)

    //     // il2cpp_hook();

    //     // listAllLevels();
    //     // const clz = C ("Assembly-CSharp", "DownLoadTask");
    //     // hookIl2cppClassFuns(clz, {
    //     //    [clz.method('.ctor').virtualAddress.toString()] : {
    //     //         nparas: 10, 
    //     //         enterFun(args, tstr, thiz) {
    //     //             const filePath = new Il2Cpp.String(args[1]);
    //     //             const url = new Il2Cpp.String(args[2]);
    //     //             console.log(`${tstr} filePath: ${filePath.content} url:${url.content}`)
    //     //         },
    //     //    },
    //     // });

    // });

}

const native_test_main_0 = ()=>{


    console.log(JSON.stringify(MyFrida.getELFInfoInModule('libil2cpp.so')))
    const patchlib = patchlibinfo.load('/data/local/tmp/libpatchgame.so', [
        'libil2cpp.so',
        ],
        {
            ... MyFrida.frida_symtab,
            pICallMap : Process.getModuleByName('libil2cpp.so').base.add(0x4323108).sub(0x100000),
        }
    )

    if(0) {
        const p = patchlib.symbols.init;
        if(p){
            new NativeFunction(p, 'int', [])();
        }
    }

    if (0) {
        const soname = 'libil2cpp.so'
        console.log('ok')

        const hooks: {
            p: NativePointer,
            name: string,
            opts: MyFrida.HookFunActionOptArgs,
        }[] = [
                {
                    p: Module.getExportByName(null, 'dlopen'), name: 'dlopen', opts: {
                        hide: true,
                        enterFun(args, tstr, thiz) {
                            const soname = path.basename(args[0].readUtf8String() || '')
                            console.log(tstr, `soname: ${soname}`)
                        },
                    }
                }
            ];

        [
            // ... hooks,
        ].forEach((h: {
            p: NativePointer,
            name: string,
            opts: MyFrida.HookFunActionOptArgs,
        }) => {
            console.log(`hook ${h.name} ${JSON.stringify(h.opts)}`)
            const { p, name, opts } = h;
            MyFrida.HookAction.addInstance(p, new MyFrida.HookFunAction({
                ...opts,
                name,
            }))
        })

        const m = Process.getModuleByName('libunity.so');
        console.log(m, m.path)

        const p = Process.getModuleByName('libil2cpp.so').base.add(0x0411e580).sub(0x100000);
        MyFrida.dumpMemory(p,);
        MyFrida.dumpMemory(p.readPointer(),);
    }

    Il2Cpp.perform(()=>{
        console.log(`Unity version: ${Il2Cpp.unityVersion}`)
    });


}

const native_test_main= ()=>{
    const sonames = [
        'libil2cpp.so',
        'libunity.so',
    ];

    if (0) {
        Process.setExceptionHandler(function (exception) {
            console.log(JSON.stringify(exception))

        });
    }
    if (0) {
        console.log(JSON.stringify(MyFrida.getELFInfoInModule(sonames[0])))
    }
    if(0){
        Il2Cpp.perform(()=>{
            console.log(`Unity version: ${Il2Cpp.unityVersion}`)
        })
    }
    if(1){

        const sohooks :{[key:string]:{
            offset: NativePointer|string,
            name: string,
            opts: MyFrida.HookFunActionOptArgs,
        }[] } = {
            'libil2cpp.so' : [],
            'libunity.so' : [
                {
                    offset:ptr(0x00d11dfc),
                    name: 'scripting_method_invoke(ScriptingMethodPtr, ScriptingObjectPtr, ScriptingArguments&, ScriptingExceptionPtr*, bool)',
                    opts:{},
                },
                {
                    offset:ptr(0x013283b0),
                    name: 'unwindstack::Memory::ReadFully',
                    opts:{},
                },
            ],

        }

        Interceptor.attach(Module.getExportByName(null,'dlopen'), {
            onEnter(args) {
                const soname = path.basename(args[0].readUtf8String() || '')
                console.log(`soname: ${soname}`)
                this.soname = soname
            },
            onLeave(retval) {
                if(retval.isNull()) return ;
                console.log(`soname: ${this.soname}`)
                if(sohooks[this.soname] != undefined){

                    const _soname =  this.soname;

                    const hooks = sohooks[_soname];

                    hooks.forEach((h: {
                        offset: NativePointer|string,
                        name: string,
                        opts: MyFrida.HookFunActionOptArgs,
                    }) => {
                        console.log(`hook ${h.name} ${JSON.stringify(h.opts)}`)
                        const { offset: offset, name, opts } = h;
                        const p = 
                            (typeof offset==='string')?
                            Module.getExportByName(_soname,offset):
                            Process.getModuleByName(_soname).base.add(offset).sub(0x100000);
                        MyFrida.HookAction.addInstance(p, new MyFrida.HookFunAction({
                            ...opts,
                            name,
                        }))
                    })
                }
            },
        })

    }


}

console.log('##################################################')
// Java.perform(il2cpp_main_cheat_android);
// Java.perform(il2cpp_main);
Java.perform(native_test_main)

