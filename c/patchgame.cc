

#include <android/input.h>

#include "utils.h"
#include "imgui/imgui.h"
#include "imgui/imgui_wrapper.h"
#include "imgui/imgui_impl_opengl3.h"
#include "imgui/imgui_impl_android.h"


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
                //ImVec4 color; 
                // if(show) color = ImVec4(1.0f, 1.0f, 0.0f, .7f);
                // else color = ImVec4(1.0f, 1.0f, 0.0f, .0f);

                // DrawCircle(100, 100, 50, true, color);

                //ImDrawList* draw_list = ImGui::GetWindowDrawList();
                auto background = ImGui::GetBackgroundDrawList();

                if(show){

                    background->AddCircle(
                            ImVec2(200, 200), 
                            100, 
                            ImGui::GetColorU32(ImGuiCol_Text));
                }
                //float radius = 30.0f;
                //ImU32 color = ImColor(255, 0, 0, 255); // Red color
                //ImVec2 center(60,60);
                //if(show) draw_list->AddCircleFilled(center, radius, color);

            ImGui::Render();


            ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    }

    return 0;
}


extern "C" __attribute__((visibility("default"))) void processInputEvent(AInputEvent* event) {
    if (AInputEvent_getType(event) == AINPUT_EVENT_TYPE_KEY) {
        int32_t action = AKeyEvent_getAction(event);
        int32_t keyCode = AKeyEvent_getKeyCode(event);
        int32_t keyDown = action == AKEY_EVENT_ACTION_DOWN;
        LOG_INFOS("keyCode %d, keyDown %d",  keyCode, keyDown);

        if(keyCode == 96 && keyDown){
            show = !show;
            LOG_INFOS("show %d", show);
            auto draw_list = ImGui::GetBackgroundDrawList();
        }

    }
}
