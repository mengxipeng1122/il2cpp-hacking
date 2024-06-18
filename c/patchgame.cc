

#include <android/input.h>
#include <string>
#include <vector>

#include "utils.h"
#include "imgui/imgui.h"
#include "imgui/imgui_wrapper.h"
#include "imgui/imgui_impl_opengl3.h"
#include "imgui/imgui_impl_android.h"

struct DiffPosition {
    int x;
    int y;
};


void DrawLine(ImVec2 start, ImVec2 end, ImVec4 color) {
      auto background = ImGui::GetBackgroundDrawList();

      if(background) {
          background->AddLine(start, end, ImColor(color.x, color.y, color.z, color.w));
      }
}

void DrawBox(float x, float y, float z, float w, ImVec4 color) {
    ImVec2 v1(x, y);
    ImVec2 v2(x + z, y);
    ImVec2 v3(x + z, y + w);
    ImVec2 v4(x, y + w);

    DrawLine(v1, v2, color);
    DrawLine(v2, v3, color);
    DrawLine(v3, v4, color);
    DrawLine(v4, v1, color);
}

void DrawCircle(float X, float Y, float radius, bool filled, ImVec4 color) {
    auto background = ImGui::GetBackgroundDrawList();

    if(background) {
        if(filled) {
            background->AddCircleFilled(ImVec2(X, Y), radius, ImColor(color.x, color.y, color.z, color.w));
        } else {
            background->AddCircle(ImVec2(X, Y), radius, ImColor(color.x, color.y, color.z, color.w));
        }
    }
}

void DrawText2(float fontSize, ImVec2 position, ImVec4 color, const char *text) {
    auto background = ImGui::GetBackgroundDrawList();

    if(background) {
        background->AddText(NULL, fontSize, position, ImColor(color.x, color.y, color.z, color.w), text);
    }
}

static bool show = true;
static std::vector<DiffPosition> g_allDiffPositions;

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

    else {

            ImGui_ImplOpenGL3_NewFrame();
            ImGui_ImplAndroid_NewFrame();

            ImGuiIO& io = ImGui::GetIO();
            ImGui::NewFrame();

                if(show){
                    auto background = ImGui::GetBackgroundDrawList();

                    for(auto it = g_allDiffPositions.begin(); it!=g_allDiffPositions.end(); it++){
                        auto DiffPosition = *it;
                        auto x = DiffPosition.x;
                        auto y = DiffPosition.y;
                        background->AddCircleFilled(
                            ImVec2(x,screenHeight-y),
                            30.f,
                            IM_COL32(255, 100, 100, 155) 
                        );
                    }

                }

            ImGui::Render();

            ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    }

    return 0;
}


extern "C" __attribute__((visibility("default"))) void toggleShow() {
    show = !show;
    LOG_INFOS("show %d", show);
}

extern "C" __attribute__((visibility("default"))) void processInputEvent(AInputEvent* event) {
    if (AInputEvent_getType(event) == AINPUT_EVENT_TYPE_KEY) {
        int32_t action = AKeyEvent_getAction(event);
        int32_t keyCode = AKeyEvent_getKeyCode(event);
        int32_t keyDown = action == AKEY_EVENT_ACTION_DOWN;
        LOG_INFOS("keyCode %d, keyDown %d",  keyCode, keyDown);

        if(keyCode == 96 && keyDown){
            toggleShow();
            // auto draw_list = ImGui::GetBackgroundDrawList();
        }

    }
}


extern "C" __attribute__((visibility("default"))) void addDiff (int x, int y){

    g_allDiffPositions.push_back({
        x,y
    });
    
}

extern "C" __attribute__((visibility("default"))) void clearDiffs (){
    g_allDiffPositions.clear();
    
}
