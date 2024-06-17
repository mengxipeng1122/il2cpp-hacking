
import 'frida-il2cpp-bridge'
import * as path from 'path'

interface Position {
    x: number,
    y: number,
    z: number
}

interface Rotation {
    x: number,
    y: number,
    z: number
}

interface Scale {
    x: number,
    y: number,
    z: number
}

interface Quternion {
    x: number,
    y: number,
    z: number,
    w: number

}

export function parseQuaternion (quaternion:Il2Cpp.Object) {

    const x = quaternion.field('x').value as number;
    const y = quaternion.field('y').value as number;
    const z = quaternion.field('z').value as number;
    const w = quaternion.field('w').value as number;

    return {x, y, z, w}

}


function displayTransform(transform: Il2Cpp.Object, depth: number = 0): void {
    let indents = '   '.repeat(depth);
    const name = (transform.method('get_name').invoke() as Il2Cpp.String).toString();

    const position = transform.method('get_position'    ).invoke() as Il2Cpp.Object;
    const rotation = transform.method('get_rotation'    ).invoke() as Il2Cpp.Object;
    const scale    = transform.method('get_localScale'  ).invoke() as Il2Cpp.Object;

    const childCount = transform.method('get_childCount').invoke() as number;

    for(let t=0; t<childCount; t++){
        const child = transform.method('GetChild').invoke(t) as Il2Cpp.Object;
        displayTransform(child, depth + 1);
    }

}


interface TransformInfo  {
    name:string,

    position : {x:number, y:number, z:number},
    rotation : {x:number, y:number, z:number},
    scale    : {x:number, y:number, z:number},
    
    children : TransformInfo[] ,

};

export const parseVector3 = (v:Il2Cpp.Object) =>{

    return {
        x : v.field('x').value as number,
        y : v.field('y').value as number,
        z : v.field('z').value as number,
    }

}

const dumpTransform = (transform:Il2Cpp.Object): TransformInfo =>{

    const name = (transform.method('get_name').invoke() as Il2Cpp.String).toString();

    const position = transform.method('get_position'    ).invoke() as Il2Cpp.Object;
    const rotation = transform.method('get_rotation'    ).invoke() as Il2Cpp.Object;
    const scale    = transform.method('get_localScale'  ).invoke() as Il2Cpp.Object;

    const children : TransformInfo[] = [];

    const childCount = transform.method('get_childCount').invoke() as number;

    for(let t=0; t<childCount; t++){
        const child = transform.method('GetChild').invoke(t) as Il2Cpp.Object;
        children.push(dumpTransform(child))
    }

    return  {

        name,

        position : parseVector3(position),
        
        rotation : parseVector3(rotation),

        scale    : parseVector3(scale   ),

        children,

    };
}

export const dumpCurrentScene = (display:boolean=false)=>{

    const {activateScene} = dumpScenes();

    const rootCount = activateScene.method('get_rootCount')
        .invoke() as number;

    const rootGameObjectsArray = activateScene.method('GetRootGameObjects')
        .invoke() as Il2Cpp.Array;

    const rootTransforms : TransformInfo[] = [];

    if(display){

        console.log(`Root gameobjects length: ${rootGameObjectsArray.length}`)

    }

    for(const item of rootGameObjectsArray){
        const gameObject = item as Il2Cpp.Object;
        //CheckVisibility(gameObject, 0);
        const transform = gameObject.method('get_transform').invoke() as Il2Cpp.Object;
        if(display){
            displayTransform(transform)
        }
        rootTransforms.push(dumpTransform(transform));
    }

    return {
        rootCount,
        rootGameObjects: rootTransforms,
    }

}

export const dumpScenes = ()=>{

    const UnityEngine_SceneManagement_SceneManager = Il2Cpp.domain
        .assembly('UnityEngine.CoreModule').image
        .class('UnityEngine.SceneManagement.SceneManager');

    const sceneCount = UnityEngine_SceneManagement_SceneManager.method('get_sceneCount')
        .invoke() as number;

    const activateScene = UnityEngine_SceneManagement_SceneManager.method('GetActiveScene')
        .invoke() as Il2Cpp.Object;
    
    const activateSceneName = (activateScene.method('get_name').invoke() as Il2Cpp.String).toString();

    return {
        sceneCount,
        activateScene,
        activateSceneName,
    }

}

export const listGameObjects = (includeInactive:boolean=false) => {

    const UnityEngine_GameObject    = C("UnityEngine.CoreModule",'UnityEngine.GameObject');

    const UnityEngine_Object        = C("UnityEngine.CoreModule",'UnityEngine.Object');

    const allGameObjectsArray       = UnityEngine_Object.method('FindObjectsOfType')
        .overload('System.Type','System.Boolean')
        .invoke(UnityEngine_GameObject.type.object,includeInactive) as Il2Cpp.Array;

    console.log(`All gameobjects length: ${allGameObjectsArray.length}`)

    const allGameObjects : any[] = [];

    for(const item of allGameObjectsArray) {
        const go = item as Il2Cpp.Object;
        const visible = IsGameObjectVisible2D(go);
        const name = ( go.method('get_name').invoke() as Il2Cpp.String).toString();
        const UnityEngine_Component    = C("UnityEngine.CoreModule",'UnityEngine.Component');
        const components = go
            .method('GetComponents')
            .overload()
            .inflate(UnityEngine_Component)
            .invoke() as Il2Cpp.Array;

        const gameObject = parseGameObject(go);
        //if(visible)
        {
            allGameObjects.push(gameObject);
        }
        // console.log(` GameObject: ${name} ${JSON.stringify(gameObject.transform.screen_position)}`);
    }

    return {
        allGameObjectsArray,
        allGameObjects,
    };

}

export const listTextures= (dumpDir:string='')=>{
    const UnityEngine_Object = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image
        .class('UnityEngine.Object');

    const UnityEngine_Texture = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image
        .class('UnityEngine.Texture');

    const UnityEngine_ImageConversion = Il2Cpp.domain.assembly("UnityEngine.ImageConversionModule").image
        .class('UnityEngine.ImageConversion');

    const Utility= Il2Cpp.domain.assembly("Assembly-CSharp").image
        .class('Utility');

    let  allTexturesArray :Il2Cpp.Array | null=null;

    if( UnityEngine_Object.tryMethod("FindObjectsOfType", 1) != null){
        allTexturesArray = UnityEngine_Object.method('FindObjectsOfType').overload('System.Type') 
            .invoke(UnityEngine_Object.type.object) as  Il2Cpp.Array;
    }

    if( UnityEngine_Object.tryMethod("FindObjectsOfType", 2) != null ){

        allTexturesArray = UnityEngine_Object.method('FindObjectsOfType').overload('System.Type', 'System.Boolean') 
            .invoke(UnityEngine_Texture.type.object, true) as Il2Cpp.Array;
    }

    if(!allTexturesArray) throw new Error(`can not find FindObjectsOfType`);


    console.log(`All textures: ${allTexturesArray.length}`)

    let idx = 0;

    for(const item of allTexturesArray){
        const texture = item as Il2Cpp.Object;
        const name = (texture.method('get_name').invoke() as Il2Cpp.String ).toString();
        const width = texture.method('get_width').invoke() as number;
        const height= texture.method('get_height').invoke() as number;
        const isReadable = texture.method('get_isReadable').invoke() as boolean;
        console.log(name,  isReadable, width, height);

        if(texture.class.name == 'Texture2D' && isReadable){
            if (dumpDir) {
                const dumpFile = path.join(dumpDir, idx.toString().padStart(8, '0') + '.png');
                console.log(`Dumping ${name} to ${dumpFile}`) 
                const bytes = UnityEngine_ImageConversion.method('EncodeToPNG').invoke(texture) as Il2Cpp.Array;
                const dumpFileString = Il2Cpp.string(dumpFile);
                Utility.method('WriteFile').invoke(dumpFileString, bytes);
            }
        }

        idx++;

        //const c = texture.method('GetPixel').invoke(1,1);
        //console.log(c);

//        UnityEngine.Color GetPixel(System.Int32 x, System.Int32 y); 
    }

}


export const listMeshes = ()=>{
    const UnityEngine_Object = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image
        .class('UnityEngine.Object');

    const UnityEngine_Mesh = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image
        .class('UnityEngine.Mesh');

    const allMeshesArray = UnityEngine_Object.method('FindObjectsOfType').overload('System.Type')
        .invoke(UnityEngine_Mesh.type.object) as Il2Cpp.Array;

    console.log(`All meshes: ${allMeshesArray.length}`)

    for(const item of allMeshesArray) {
        const mesh = item as Il2Cpp.Object;
        const name = (mesh.method('get_name').invoke() as Il2Cpp.String ).toString();
        const vertexCount = mesh.method('get_vertexCount').invoke() as number;
        console.log(name, mesh.class.name, vertexCount);
    }

}

export const il2cpp_hook = ()=>{
    const Assembly_CSharp = Il2Cpp.domain.assembly('Assembly-CSharp');
    Il2Cpp.trace()
        .assemblies(Assembly_CSharp)
        //.filterClasses(c=>!c.name.includes('GuruFramework'))
        .and()
        .attach()
}

export const parseSystem_Collections_Generic_List = (l:Il2Cpp.Object) =>{

    const count = l.method('get_Count').invoke() as number;

    const list : any[] = [];

    for(let t = 0;t<count ;t++){
        const item = l.method('get_Item').invoke(t) as Il2Cpp.Object;
        list.push(item)
    }

    return list;


}

export const parseInt32Arrray = (a:Il2Cpp.Array) =>{

    const arr : number [] = []

    for(const item of a){

        const n = item as number;

        arr.push(n)

    }

    return arr;

}

export const getUnityVersion = ()=>{
    const UnityEngine_Application = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image
        .class('UnityEngine.Application');
    const Version = UnityEngine_Application.method('get_unityVersion').invoke() as Il2Cpp.String;
    return Version.toString();
}

export const parseVector2Array = (arr:Il2Cpp.Array) =>{
    const vArr : {x:number , y:number} [] = [];
    for(const item of arr) {
        const v = item as Il2Cpp.Object;
        vArr.push(parseVector2(v))
    }
    return vArr;
}

export const parseGameObject = (go:Il2Cpp.Object) =>{

    const name = (go.method('get_name').invoke() as Il2Cpp.String ).toString();

    const transform = parseTransform(go.method('get_transform').invoke() as Il2Cpp.Object);
    const activate = go.method('get_active').invoke() as boolean;
    // if (activate) {
    //     console.log(`name: ${name} transform: ${JSON.stringify(transform)}`)
    // }

    return {name, transform, activate};

}


export const parseVector2 = (v:Il2Cpp.Object) =>{
    return {
        x : v.field('x').value as number,
        y : v.field('y').value as number,
    }
}

export const C = (assemblyName:string, className:string) =>{
    return Il2Cpp.domain.assembly(assemblyName).image.class(className);
}

export const findObjects = (clz:Il2Cpp.Class, dump:boolean=false) => {

    const UnityEngine_Object =C("UnityEngine.CoreModule",'UnityEngine.Object');

    const instances = UnityEngine_Object.method('FindObjectsOfType').overload('System.Type')
        .invoke(clz.type.object) as Il2Cpp.Array;

    if(instances.length<=0) throw new Error(`can not find instances of class ${clz.name} `);

    const instance =  instances.get(0);
    if(dump){
        console.log(`Found ${instances.length} instances of class ${clz.name} `);
        console.log(`The first instance: ${instance}`);
    }

    return instance as Il2Cpp.Object;

}

export const getScreenResolution = ()=>{
    const UnityEngine_Screen =C("UnityEngine.CoreModule",'UnityEngine.Screen');
    const width = UnityEngine_Screen.method('get_width' ).invoke() as number;
    const height= UnityEngine_Screen.method('get_height').invoke() as number;

    return {
        width,
        height,
    }
}

export const parseTransform   = (transform:Il2Cpp.Object) =>{
    const UnityEngine_Camera = C('UnityEngine.CoreModule',"UnityEngine.Camera");
    const cam = UnityEngine_Camera.method('get_current').invoke() as Il2Cpp.Object;
    const WorldToScreenPoint = cam.method('WorldToScreenPoint').overload('UnityEngine.Vector3');
    const ScreenToViewportPoint= cam.method('ScreenToViewportPoint').overload('UnityEngine.Vector3');

    const position              = transform.method('get_position').invoke() as Il2Cpp.Object;
    const localPosition         = transform.method('get_localPosition').invoke() as Il2Cpp.Object;
    const screen_position       = WorldToScreenPoint.invoke(position) as Il2Cpp.Object
    const screen_localPosition  = WorldToScreenPoint.invoke(localPosition) as Il2Cpp.Object
    const viewport_position       = ScreenToViewportPoint.invoke(screen_position) as Il2Cpp.Object;
    const viewport_localPosition  = ScreenToViewportPoint.invoke(screen_localPosition) as Il2Cpp.Object;

    const rotation = parseQuaternion(transform.method('get_rotation').invoke() as Il2Cpp.Object);
    const localRotation = parseQuaternion(transform.method('get_localRotation').invoke() as Il2Cpp.Object);
    const localScale = parseVector3(transform.method('get_localScale').invoke() as Il2Cpp.Object);


    return {
        position                : parseVector3(position                 ),
        localPosition           : parseVector3(localPosition            ),

        screen_position         : parseVector3(screen_position          ),
        screen_localPosition    : parseVector3(screen_localPosition     ),
        viewport_position       : parseVector3(viewport_position        ),
        viewport_localPosition  : parseVector3(viewport_localPosition   ),

        rotation,
        localRotation,
        localScale,
    }
}

export const parseCamera = (cam?:Il2Cpp.Object) =>{
    const UnityEngine_Camera = C('UnityEngine.CoreModule',"UnityEngine.Camera");
    const camerasCount =  UnityEngine_Camera.method('GetAllCamerasCount').invoke() as number;
    console.log(`Cameras count: ${camerasCount}`);

    cam = cam || UnityEngine_Camera.method('get_current').invoke() as Il2Cpp.Object;

    console.log(`Rect: ${cam.method('get_rect').invoke()}`);
}


export const IsRendererVisibleFrom2D = (renderer:Il2Cpp.Object, camera:Il2Cpp.Object) => {

    const camPos = (camera.method('get_transform').invoke() as Il2Cpp.Object)
        .method('get_position').invoke() as Il2Cpp.Object;

    const get_sprite = renderer.tryMethod('get_sprite');

    if(get_sprite!=null && !get_sprite.isNull()){

        const sprite = get_sprite.invoke() as Il2Cpp.Object;
        if(sprite!=null && !sprite.isNull()) {

            const get_bounds = sprite.tryMethod('get_bounds');
            if (get_bounds != null && !get_bounds.isNull()) {

                console.log(`get_bounds ${sprite} ${sprite.method('get_bounds')}`)

                const bounds = sprite.method('get_bounds').invoke() as Il2Cpp.Object;

                // Check each corner to see if it's inside the camera's view

                const min = bounds.method('get_min').invoke() as Il2Cpp.Object;
                const max = bounds.method('get_max').invoke() as Il2Cpp.Object;

                const minX = min.field('x').value as number;
                const minY = min.field('y').value as number;
                const maxX = max.field('x').value as number;
                const maxY = max.field('y').value as number;

                const UnityEngine_Vector3 = C("UnityEngine.CoreModule", "UnityEngine.Vector3");

                for (let x = 0; x <= 1; x++) {
                    for (let y = 0; y <= 1; y++) {
                        const test = UnityEngine_Vector3.method("get_zero").invoke() as Il2Cpp.Object;
                        test.field('x').value = (x == 0) ? minX : maxX;
                        test.field('y').value = (y == 0) ? minY : maxY;
                        test.field('z').value = camPos.field('z').value;

                        const screenPointTest = camera.method('WorldToScreenPoint').overload('UnityEngine.Vector3').invoke(test) as Il2Cpp.Object;
                        const viewportTest = camera.method('ScreenToViewportPoint').overload('UnityEngine.Vector3')
                            .invoke(screenPointTest) as Il2Cpp.Object;

                        const viewportTestX = viewportTest.field('x').value as number;
                        const viewportTestY = viewportTest.field('y').value as number;

                        // Check if it's inside camera's view
                        if (viewportTestX >= 0
                            && viewportTestX <= 1
                            && viewportTestY >= 0
                            && viewportTestY <= 1) {
                            return true;
                        }
                    }
                }
            }
        }

    }

    // If none of the corners are in view, the object is not visible
    return false;
}

export const CheckVisibility = (obj:Il2Cpp.Object, depth:number = 0) => {

    let indents = '   '.repeat(depth);
    console.log(indents, obj.toString());

    const visible = IsGameObjectVisible2D(obj);
    if(visible){
                console.log("Visible GameObject: " + (obj.method('get_name').invoke() as Il2Cpp.String).toString());
            }
    const transform = obj.method('get_transform').invoke() as Il2Cpp.Object;
    const childCount =  transform.method('get_childCount').invoke() as number;

    // Recursively check the children of the GameObject
    for (let i = 0; i < childCount; i++)
    {
        const child =  (transform.method('GetChild').invoke(i) as Il2Cpp.Object)
            .method('get_gameObject').invoke() as Il2Cpp.Object;

        CheckVisibility(child, depth+1)
    }
}


const IsGameObjectVisible2D = (obj:Il2Cpp.Object):boolean =>{

    const UnityeEngine_Renderer = C("UnityEngine.CoreModule", "UnityEngine.Renderer");
    const UnityEngine_Camera = C('UnityEngine.CoreModule', "UnityEngine.Camera");
    const cam = UnityEngine_Camera.method('get_current').invoke() as Il2Cpp.Object;

    const name = (obj.method('get_name').invoke() as Il2Cpp.String).toString();

    // check activate
    const activate = obj.method('get_active').invoke() as boolean;
    if (activate) {

        const UnityEngine_Component = C("UnityEngine.CoreModule", 'UnityEngine.Component');
        const components = obj
            .method('GetComponents')
            .overload('System.Type')
            //.inflate(UnityEngine_Component)
            .invoke(UnityeEngine_Renderer.type.object) as Il2Cpp.Array;
        for (const item of components) {
            const component = item as Il2Cpp.Object;
            const get_enabled = component.tryMethod('get_enabled');
            if (get_enabled != null) {
                const enabled = get_enabled.invoke() as boolean;
                if (enabled) {

                    console.log(`trying ${name} ${component.toString()}`)

                    if (IsRendererVisibleFrom2D(component, cam))
                        return true;

                }
            }

        }
    }
    return false;
}
