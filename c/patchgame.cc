

#include "utils.h"
#include "imgui/imgui.h"
#include "imgui/imgui_wrapper.h"
#include "imgui/imgui_impl_opengl3.h"
#include "imgui/imgui_impl_android.h"


// extern "C" __attribute__((visibility("default"))) int init (int width, int height) {
// 
//     LOG_INFOS("go here %dx%d", width, height);
//     
// //    imguiInit(width, height);
//     return 0;
// }

extern "C" __attribute__((visibility("default"))) int hookGL (int width, int height) {

    static bool first = true;
    static int screenWidth = 0;
    static int screenHeight = 0;
    if (first) {
        LOG_INFOS("ImGui init: %dx%d", width, height);
        imguiInit(width, height);
        screenWidth = width;
        screenHeight = height;
        first = false;
    }    

    {


        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplAndroid_NewFrame();

        {
        ImGuiIO& io = ImGui::GetIO();
        ImGui::NewFrame();
            ImGui::SetNextWindowPos(ImVec2(20, 20), ImGuiCond_FirstUseEver);
            ImGui::SetNextWindowSize(ImVec2(300, 680), ImGuiCond_FirstUseEver);
            ImGui::Begin("Nodes Navigator"); 
            ImGui::End();
        ImGui::Render();
        }

        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    }


    return 0;
}

