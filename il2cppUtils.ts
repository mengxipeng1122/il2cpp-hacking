
import 'frida-il2cpp-bridge'

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