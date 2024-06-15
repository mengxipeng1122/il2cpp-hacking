
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


function displayTransform(transform: Il2Cpp.Object, depth: number = 0): void {
    let indents = '   '.repeat(depth);
    const name = (transform.method('get_name').invoke() as Il2Cpp.String).toString();

    const position = transform.method('get_position'    ).invoke() as Il2Cpp.Object;
    const rotation = transform.method('get_rotation'    ).invoke() as Il2Cpp.Object;
    const scale    = transform.method('get_localScale'  ).invoke() as Il2Cpp.Object;
    console.log(`${indents} ${name} Position: ${JSON.stringify(parseVector3(position))} Rotation: ${JSON.stringify(parseVector3(rotation))} Scale: ${JSON.stringify(parseVector3(scale))} ` );

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

const parseVector3 = (v:Il2Cpp.Object) =>{

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

export const listGameObjects = (includeInactive:boolean=false)=>{

    const UnityEngine_GameObject = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image
        .class('UnityEngine.GameObject');

    const UnityEngine_Object = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image
        .class('UnityEngine.Object');

    const allGameObjets = UnityEngine_Object.method('FindObjectsOfType').overload('System.Type','System.Boolean')
        .invoke(UnityEngine_GameObject.type.object,includeInactive) as Il2Cpp.Array;

    console.log(`All gameobjects length: ${allGameObjets.length}`)

    const allGameObjectNames : string[] = [];

    for(const item of allGameObjets) {
        const go = item as Il2Cpp.Object;
        const name = go.method('get_name').invoke() as Il2Cpp.String;
        allGameObjectNames.push(name.toString());
    }

    return {
        allGameObjets,
        allGameObjectNames,
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


export const parseVector2 = (v:Il2Cpp.Object) =>{
    return {
        x : v.field('x').value as number,
        y : v.field('y').value as number,
    }
}

export const c = (assemblyName:string, className:string) =>{
    return Il2Cpp.domain.assembly(assemblyName).image.class(className);
}

export const findObjects = (clz:Il2Cpp.Class, dump:boolean=false) => {

    const UnityEngine_Object =c("UnityEngine.CoreModule",'UnityEngine.Object');

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
    const UnityEngine_Screen =c("UnityEngine.CoreModule",'UnityEngine.Screen');
    const width = UnityEngine_Screen.method('get_width' ).invoke() as number;
    const height= UnityEngine_Screen.method('get_height').invoke() as number;

    return {
        width,
        height,
    }

}