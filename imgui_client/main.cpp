#include "imgui.h"
#include "imgui_internal.h"
#include "imgui_impl_sdl2.h"
#include "imgui_impl_opengl3.h"
#include <SDL.h>
#include <SDL_opengl.h>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <cstdarg>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

using json = nlohmann::json;

// ─────────────────────────────────────────────────────────────
// Ring buffer for time-series data
// ─────────────────────────────────────────────────────────────
template <typename T, size_t N>
struct RingBuffer {
    T buf[N]{};
    size_t head = 0;
    size_t cnt = 0;

    void push(T v) {
        buf[head] = v;
        head = (head + 1) % N;
        if (cnt < N) cnt++;
    }
    std::vector<T> ordered() const {
        std::vector<T> v;
        v.reserve(cnt);
        if (cnt < N) {
            for (size_t i = 0; i < cnt; i++) v.push_back(buf[i]);
        } else {
            for (size_t i = 0; i < N; i++)
                v.push_back(buf[(head + i) % N]);
        }
        return v;
    }
    T latest() const {
        if (cnt == 0) return T{};
        return buf[(head + N - 1) % N];
    }
    size_t size() const { return cnt; }
    void clear() { head = 0; cnt = 0; }
};

// ─────────────────────────────────────────────────────────────
// Application state (shared between fetch thread and UI)
// ─────────────────────────────────────────────────────────────
struct AppState {
    static constexpr int kHistory = 120;

    std::mutex mtx;
    json       latest;
    bool       has_data    = false;
    bool       bpf_enabled = false;
    std::string server_url = "http://localhost:8080";
    std::string error_msg;
    int        cpu_count = 4;

    // /proc time series
    std::vector<RingBuffer<float, kHistory>> cpu_core;
    RingBuffer<float, kHistory> cpu_total;
    RingBuffer<float, kHistory> mem_pct;
    RingBuffer<float, kHistory> disk_read;
    RingBuffer<float, kHistory> disk_write;
    RingBuffer<float, kHistory> net_rx;
    RingBuffer<float, kHistory> net_tx;
    RingBuffer<float, kHistory> load1;
    RingBuffer<float, kHistory> load5;
    RingBuffer<float, kHistory> load15;

    // BPF time series
    RingBuffer<float, kHistory> page_alloc;
    RingBuffer<float, kHistory> page_free;
    RingBuffer<float, kHistory> bpf_tx_pkts;
    RingBuffer<float, kHistory> bpf_rx_pkts;

    // BPF histograms (latest snapshot)
    std::vector<std::tuple<int, int, int>> sched_hist;
    std::vector<std::tuple<int, int, int>> disk_hist;

    // BPF status per subprocess
    bool bpf_cpu_ok  = false;
    bool bpf_disk_ok = false;
    bool bpf_mem_ok  = false;
    bool bpf_net_ok  = false;
};

// ─────────────────────────────────────────────────────────────
// libcurl write callback
// ─────────────────────────────────────────────────────────────
static size_t curl_write_cb(void* ptr, size_t sz, size_t n, void* user) {
    auto* str = static_cast<std::string*>(user);
    str->append(static_cast<char*>(ptr), sz * n);
    return sz * n;
}

// ─────────────────────────────────────────────────────────────
// Background fetch thread: polls /api/stats every second
// ─────────────────────────────────────────────────────────────
static void fetch_thread(std::atomic<bool>& running, AppState& st) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        st.error_msg = "curl_easy_init failed";
        return;
    }
    std::string url = st.server_url + "/api/stats";
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 2L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);

    while (running) {
        std::string body;
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
        CURLcode rc = curl_easy_perform(curl);

        if (rc == CURLE_OK) {
            try {
                json j = json::parse(body);

                std::lock_guard<std::mutex> lk(st.mtx);
                st.latest    = std::move(j);
                st.has_data  = true;
                st.error_msg.clear();

                auto& d = st.latest;
                st.bpf_enabled = d.value("bpf_enabled", false);
                st.cpu_count   = d.value("cpu_count", 4);

                // Resize cpu_core if needed
                if ((int)st.cpu_core.size() < st.cpu_count)
                    st.cpu_core.resize(st.cpu_count);

                // CPU
                if (d.contains("cpu")) {
                    for (int i = 0; i < st.cpu_count; i++) {
                        char key[16];
                        snprintf(key, sizeof(key), "cpu%d", i);
                        float v = d["cpu"].value(key, 0.0f);
                        st.cpu_core[i].push(v);
                    }
                    st.cpu_total.push(d["cpu"].value("cpu", 0.0f));
                }

                // Memory
                if (d.contains("memory"))
                    st.mem_pct.push(d["memory"].value("percent", 0.0f));

                // Disk
                if (d.contains("disk")) {
                    st.disk_read.push(d["disk"].value("total_read_kbps", 0.0f));
                    st.disk_write.push(d["disk"].value("total_write_kbps", 0.0f));
                }

                // Network
                if (d.contains("network")) {
                    st.net_rx.push(d["network"].value("total_rx_kbps", 0.0f));
                    st.net_tx.push(d["network"].value("total_tx_kbps", 0.0f));
                }

                // Load
                if (d.contains("load")) {
                    st.load1.push(d["load"].value("load1", 0.0f));
                    st.load5.push(d["load"].value("load5", 0.0f));
                    st.load15.push(d["load"].value("load15", 0.0f));
                }

                // BPF data
                if (st.bpf_enabled && d.contains("bpf")) {
                    auto& bpf = d["bpf"];

                    if (bpf.contains("data")) {
                        auto& bd = bpf["data"];
                        if (bd.contains("mem")) {
                            st.page_alloc.push(bd["mem"].value("page_allocs", 0.0f));
                            st.page_free.push(bd["mem"].value("page_frees", 0.0f));
                        }
                        if (bd.contains("net")) {
                            st.bpf_tx_pkts.push(bd["net"].value("tx_pkts", 0.0f));
                            st.bpf_rx_pkts.push(bd["net"].value("rx_pkts", 0.0f));
                        }
                    }

                    if (bpf.contains("histograms")) {
                        auto& h = bpf["histograms"];
                        st.sched_hist.clear();
                        if (h.contains("latsched")) {
                            for (auto& b : h["latsched"])
                                st.sched_hist.emplace_back(b[0], b[1], b[2]);
                        }
                        st.disk_hist.clear();
                        if (h.contains("disk_lat")) {
                            for (auto& b : h["disk_lat"])
                                st.disk_hist.emplace_back(b[0], b[1], b[2]);
                        }
                    }

                    if (bpf.contains("status")) {
                        auto& stt = bpf["status"];
                        st.bpf_cpu_ok  = stt.value("cpu",  json::object()).value("running", false);
                        st.bpf_disk_ok = stt.value("disk", json::object()).value("running", false);
                        st.bpf_mem_ok  = stt.value("mem",  json::object()).value("running", false);
                        st.bpf_net_ok  = stt.value("net",  json::object()).value("running", false);
                    }
                }
            } catch (const std::exception& e) {
                std::lock_guard<std::mutex> lk(st.mtx);
                st.error_msg = std::string("JSON: ") + e.what();
            }
        } else {
            std::lock_guard<std::mutex> lk(st.mtx);
            st.error_msg = std::string("HTTP: ") + curl_easy_strerror(rc);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
    curl_easy_cleanup(curl);
}

// ─────────────────────────────────────────────────────────────
// Mini plot widget – line chart drawn with ImDrawList
// ─────────────────────────────────────────────────────────────
static ImU32 plot_colors[] = {
    IM_COL32(88,  166, 255, 255),  // blue
    IM_COL32(63,  185, 80,  255),  // green
    IM_COL32(210, 153, 34,  255),  // yellow
    IM_COL32(248, 81,  73,  255),  // red
    IM_COL32(163, 113, 247, 255),  // purple
    IM_COL32(121, 192, 255, 255),  // light blue
    IM_COL32(86,  211, 100, 255),  // light green
    IM_COL32(227, 179, 65,  255),  // light yellow
    IM_COL32(255, 123, 114, 255),  // light red
    IM_COL32(210, 168, 255, 255),  // light purple
    IM_COL32(126, 231, 135, 255),
    IM_COL32(240, 136, 62,  255),
    IM_COL32(255, 161, 152, 255),
    IM_COL32(219, 111, 40,  255),
    IM_COL32(255, 128, 191, 255),
};

static float clamp_range(float& ymin, float& ymax,
                        const std::vector<float>& data) {
    if (data.empty()) { ymin = -10; ymax = 10; return 20; }
    auto [lo, hi] = std::minmax_element(data.begin(), data.end());
    float data_min = *lo, data_max = *hi;
    if (data_max - data_min <= 0) {
        ymin = data_min - 10; ymax = data_max + 10;
    } else {
        float pad = (data_max - data_min) * 0.1f;
        ymin = data_min - pad;
        ymax = data_max + pad;
    }
    float r = ymax - ymin;
    return r > 0 ? r : 1;
}

static void PlotLine(const char* label, const std::vector<float>& data,
                     float ymin, float ymax,
                     const ImVec2& size, int color_idx = 0) {
    ImGuiWindow* win = ImGui::GetCurrentWindow();
    if (win->SkipItems) return;

    ImVec2 pos  = win->DC.CursorPos;
    ImVec2 sz   = ImVec2(size.x > 0 ? size.x : ImGui::GetContentRegionAvail().x, size.y);
    ImRect bb(pos, ImVec2(pos.x + sz.x, pos.y + sz.y));
    ImGui::ItemSize(bb);
    if (!ImGui::ItemAdd(bb, 0)) return;

    ImDrawList* dl = win->DrawList;
    ImU32 bg       = IM_COL32(13, 17, 23, 255);
    ImU32 border   = IM_COL32(48, 54, 61, 255);
    ImU32 grid     = IM_COL32(48, 54, 61, 80);
    ImU32 line_col = plot_colors[color_idx % 15];
    ImU32 fill_col = (line_col & 0x00FFFFFF) | 0x28000000;

    dl->AddRectFilled(bb.Min, bb.Max, bg);
    dl->AddRect(bb.Min, bb.Max, border);

    float w = bb.Max.x - bb.Min.x;
    float h = bb.Max.y - bb.Min.y;
    float range = (ymax > ymin) ? (ymax - ymin) : clamp_range(ymin, ymax, data);

    // horizontal grid
    int ng = 4;
    for (int i = 1; i < ng; i++) {
        float gy = bb.Max.y - h * (float)i / (float)ng;
        dl->AddLine(ImVec2(bb.Min.x, gy), ImVec2(bb.Max.x, gy), grid, 0.5f);
    }

    // data polyline + fill
    if (data.size() >= 2) {
        float dx = w / (float)(data.size() - 1);
        std::vector<ImVec2> pts;
        pts.reserve(data.size() + 2);
        for (size_t i = 0; i < data.size(); i++) {
            float x = bb.Min.x + i * dx;
            float y = bb.Max.y - ((data[i] - ymin) / range) * h;
            pts.push_back(ImVec2(x, ImClamp(y, bb.Min.y, bb.Max.y)));
        }
        // fill polygon: data line + bottom-right + bottom-left
        pts.push_back(ImVec2(bb.Max.x, bb.Max.y));
        pts.push_back(ImVec2(bb.Min.x, bb.Max.y));
        dl->AddConvexPolyFilled(pts.data(), (int)pts.size(), fill_col);
        dl->AddPolyline(pts.data(), (int)data.size(), line_col, 0, 1.5f);
    }

    // label + latest value
    char buf[128];
    float last_val = data.empty() ? 0.0f : data.back();
    snprintf(buf, sizeof(buf), " %s  %.1f", label, last_val);
    dl->AddText(ImVec2(bb.Min.x + 4, bb.Min.y + 3), IM_COL32(200, 200, 200, 220), buf);
}

static void PlotMultiLine(const char* label,
                          const std::vector<std::vector<float>>& series,
                          const std::vector<const char*>& names,
                          float ymin, float ymax,
                          const ImVec2& size) {
    ImGuiWindow* win = ImGui::GetCurrentWindow();
    if (win->SkipItems) return;

    ImVec2 pos = win->DC.CursorPos;
    ImVec2 sz  = ImVec2(size.x > 0 ? size.x : ImGui::GetContentRegionAvail().x, size.y);
    ImRect bb(pos, ImVec2(pos.x + sz.x, pos.y + sz.y));
    ImGui::ItemSize(bb);
    if (!ImGui::ItemAdd(bb, 0)) return;

    ImDrawList* dl = win->DrawList;
    dl->AddRectFilled(bb.Min, bb.Max, IM_COL32(13, 17, 23, 255));
    dl->AddRect(bb.Min, bb.Max, IM_COL32(48, 54, 61, 255));

    float w = bb.Max.x - bb.Min.x;
    float h = bb.Max.y - bb.Min.y;

    // auto-scale if user passed ymin==ymax
    float range;
    if (ymax > ymin) {
        range = ymax - ymin;
    } else {
        float all_min = 1e9f, all_max = -1e9f;
        for (auto& s : series) {
            if (s.empty()) continue;
            auto [lo, hi] = std::minmax_element(s.begin(), s.end());
            all_min = std::min(all_min, *lo);
            all_max = std::max(all_max, *hi);
        }
        if (all_max - all_min <= 0) { all_min -= 10; all_max += 10; }
        else { float pad = (all_max - all_min) * 0.1f; all_min -= pad; all_max += pad; }
        ymin  = all_min;
        ymax  = all_max;
        range = ymax - ymin;
        if (range <= 0) range = 1;
    }

    // horizontal grid
    int ng = 4;
    for (int i = 1; i < ng; i++) {
        float gy = bb.Max.y - h * (float)i / (float)ng;
        dl->AddLine(ImVec2(bb.Min.x, gy), ImVec2(bb.Max.x, gy),
                    IM_COL32(48, 54, 61, 80), 0.5f);
    }

    // draw each series
    size_t n = series.size();
    if (n > 0) {
        size_t max_pts = 0;
        for (auto& s : series) max_pts = std::max(max_pts, s.size());

        for (size_t si = 0; si < n; si++) {
            auto& data = series[si];
            if (data.size() < 2) continue;
            if (max_pts < 2) continue;
            float dx = w / (float)(max_pts - 1);
            std::vector<ImVec2> pts;
            pts.reserve(data.size());
            for (size_t i = 0; i < data.size(); i++) {
                float x = bb.Min.x + i * dx;
                float y = bb.Max.y - ((data[i] - ymin) / range) * h;
                pts.push_back(ImVec2(x, ImClamp(y, bb.Min.y + 1, bb.Max.y - 1)));
            }
            dl->AddPolyline(pts.data(), (int)pts.size(), plot_colors[si % 15], 0, 1.5f);
        }
    }

    // legend
    float lx = bb.Min.x + 8, ly = bb.Min.y + 4;
    for (size_t si = 0; si < n; si++) {
        char buf[64];
        float v = series[si].empty() ? 0 : series[si].back();
        snprintf(buf, sizeof(buf), "%s:%.1f", names[si], v);
        dl->AddText(ImVec2(lx, ly), plot_colors[si % 15], buf);
        lx += ImGui::CalcTextSize(buf).x + 14;
    }
}

// ─────────────────────────────────────────────────────────────
// Bar chart (histogram) widget
// ─────────────────────────────────────────────────────────────
static void PlotHistogram(const char* label,
                          const std::vector<std::tuple<int,int,int>>& buckets,
                          const ImVec2& size) {
    ImGuiWindow* win = ImGui::GetCurrentWindow();
    if (win->SkipItems) return;

    ImVec2 pos = win->DC.CursorPos;
    ImVec2 sz  = ImVec2(size.x > 0 ? size.x : ImGui::GetContentRegionAvail().x, size.y);
    ImRect bb(pos, ImVec2(pos.x + sz.x, pos.y + sz.y));
    ImGui::ItemSize(bb);
    if (!ImGui::ItemAdd(bb, 0)) return;

    ImDrawList* dl = win->DrawList;
    dl->AddRectFilled(bb.Min, bb.Max, IM_COL32(13, 17, 23, 255));
    dl->AddRect(bb.Min, bb.Max, IM_COL32(48, 54, 61, 255));

    if (buckets.empty()) {
        dl->AddText(ImVec2(bb.Min.x + 4, bb.Min.y + 4),
                    IM_COL32(139, 148, 158, 200), "No data");
        return;
    }

    size_t n = std::min(buckets.size(), size_t(40));
    float bar_w = (bb.Max.x - bb.Min.x) / (float)n;

    int max_cnt = 0;
    for (size_t i = 0; i < n; i++)
        max_cnt = std::max(max_cnt, std::get<2>(buckets[i]));
    if (max_cnt == 0) max_cnt = 1;

    float chart_h = bb.Max.y - bb.Min.y;

    for (size_t i = 0; i < n; i++) {
        auto [lo, hi, cnt] = buckets[i];
        float bh = chart_h * (float)cnt / (float)max_cnt;
        float bx = bb.Min.x + i * bar_w + 1;
        float by = bb.Max.y - bh;
        dl->AddRectFilled(ImVec2(bx, by),
                          ImVec2(bx + bar_w - 2, bb.Max.y),
                          IM_COL32(88, 166, 255, 180));
    }

    // title + max
    char buf[64];
    snprintf(buf, sizeof(buf), " %s  (max=%d)", label, max_cnt);
    dl->AddText(ImVec2(bb.Min.x + 4, bb.Min.y + 3), IM_COL32(200, 200, 200, 220), buf);
}

// ─────────────────────────────────────────────────────────────
// Stat display helper
// ─────────────────────────────────────────────────────────────
static void StatItem(const char* label, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char val[64];
    vsnprintf(val, sizeof(val), fmt, ap);
    va_end(ap);

    ImGui::BeginGroup();
    ImGui::TextColored(ImVec4(0.35f, 0.58f, 1.0f, 1.0f), "%s", val);
    ImGui::TextDisabled("%s", label);
    ImGui::EndGroup();
    ImGui::SameLine();
}

// ─────────────────────────────────────────────────────────────
// Thermal chip color helper
// ─────────────────────────────────────────────────────────────
static ImVec4 thermal_color(float temp) {
    if (temp > 75) return ImVec4(0.97f, 0.32f, 0.29f, 1.0f);  // red
    if (temp > 55) return ImVec4(0.82f, 0.60f, 0.13f, 1.0f);  // yellow
    return ImVec4(0.25f, 0.73f, 0.31f, 1.0f);                  // green
}

// ─────────────────────────────────────────────────────────────
// Panel helpers
// ─────────────────────────────────────────────────────────────
static void BeginPanel(const char* title, float x, float y, float w, float h) {
    ImGui::SetNextWindowPos(ImVec2(x, y));
    ImGui::SetNextWindowSize(ImVec2(w, h));
    ImGui::Begin(title, nullptr,
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar);
    ImGui::TextColored(ImVec4(0.35f, 0.58f, 1.0f, 1.0f), "%s", title);
    ImGui::Separator();
}

static void EndPanel() { ImGui::End(); }

static void PanelMsg(const char* msg, ImVec4 color) {
    ImVec2 sz = ImGui::GetContentRegionAvail();
    ImGui::SetCursorPos(ImVec2((sz.x - ImGui::CalcTextSize(msg).x) * 0.5f,
                               (sz.y - ImGui::GetTextLineHeight()) * 0.5f));
    ImGui::TextColored(color, "%s", msg);
}

// ─────────────────────────────────────────────────────────────
// Main dashboard rendering (fixed grid, no docking)
// ─────────────────────────────────────────────────────────────
static void RenderDashboard(AppState& st) {
    std::lock_guard<std::mutex> lk(st.mtx);

    const ImGuiViewport* vp = ImGui::GetMainViewport();
    float VW = vp->Size.x;
    float VH = vp->Size.y;
    float HDR_H = 34;
    float PW = VW * 0.5f;         // panel width (half)
    float CPU_H  = VH * 0.30f;
    float MID_H  = VH * 0.23f;
    float LOW_H  = VH * 0.22f;
    float BPF_H  = VH * 0.22f;

    // ── Header bar ──
    {
        ImGui::SetNextWindowPos(vp->Pos);
        ImGui::SetNextWindowSize(ImVec2(VW, HDR_H));
        ImGui::Begin("##hdr", nullptr,
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
            ImGuiWindowFlags_NoBringToFrontOnFocus);
        ImGui::TextColored(ImVec4(0.35f, 0.58f, 1.0f, 1.0f),
                           "bpfscript  |  RK3588 ARM64 / Linux 6.1");
        ImGui::SameLine(ImGui::GetWindowWidth() - 280);

        if (st.error_msg.empty() && st.has_data)
            ImGui::TextColored(ImVec4(0.25f, 0.73f, 0.31f, 1.0f), " connected");
        else if (!st.error_msg.empty())
            ImGui::TextColored(ImVec4(0.97f, 0.32f, 0.29f, 1.0f),
                               " %s", st.error_msg.c_str());
        else
            ImGui::TextColored(ImVec4(0.82f, 0.60f, 0.13f, 1.0f), " connecting...");

        ImGui::SameLine();
        if (st.bpf_enabled) {
            int ok = st.bpf_cpu_ok + st.bpf_disk_ok + st.bpf_mem_ok + st.bpf_net_ok;
            if (ok == 4)
                ImGui::TextColored(ImVec4(0.25f, 0.73f, 0.31f, 1.0f), " BPF:on");
            else
                ImGui::TextColored(ImVec4(0.82f, 0.60f, 0.13f, 1.0f), " BPF:partial(%d/4)", ok);
        } else {
            ImGui::TextDisabled(" BPF:off");
        }
        ImGui::End();
    }

    float y0 = vp->Pos.y + HDR_H;

    // ── Row 1: CPU (full width) ──
    {
        float x = vp->Pos.x;
        float y = y0;
        BeginPanel("CPU Usage (%)", x, y, VW, CPU_H);
        if (!st.has_data) {
            PanelMsg("Waiting for data...", ImVec4(0.55f, 0.58f, 0.62f, 1.0f));
        } else {
            std::vector<std::vector<float>> series;
            std::vector<std::string> namebuf;
            for (int i = 0; i < st.cpu_count && i < (int)st.cpu_core.size(); i++) {
                series.push_back(st.cpu_core[i].ordered());
                char b[16]; snprintf(b, sizeof(b), "cpu%d", i);
                namebuf.emplace_back(b);
            }
            series.push_back(st.cpu_total.ordered());
            namebuf.emplace_back("avg");
            std::vector<const char*> names;
            for (auto& s : namebuf) names.push_back(s.c_str());
            PlotMultiLine("CPU", series, names, 0, 100,
                          ImVec2(-1, CPU_H - 32));
        }
        EndPanel();
    }

    float y1 = y0 + CPU_H;

    // ── Row 2: Memory + Disk ──
    {
        float xL = vp->Pos.x;
        float xR = xL + PW + 2;

        // Memory
        BeginPanel("Memory", xL, y1, PW, MID_H);
        if (st.has_data && st.latest.contains("memory")) {
            auto& m = st.latest["memory"];
            StatItem("Used/MB",  "%.0f", m.value("used_mb", 0.0));
            StatItem("Avail/MB", "%.0f", m.value("available_mb", 0.0));
            StatItem("Pct",      "%.1f%%", m.value("percent", 0.0));
            StatItem("Cache",    "%.0f", m.value("cached_mb", 0.0));
            ImGui::NewLine();
            PlotLine("", st.mem_pct.ordered(), 0, 100, ImVec2(-1, MID_H - 72), 3);
        }
        EndPanel();

        // Disk I/O
        BeginPanel("Disk I/O", xR, y1, PW, MID_H);
        if (st.has_data && st.latest.contains("disk")) {
            auto& d = st.latest["disk"];
            StatItem("R KB/s", "%.0f", d.value("total_read_kbps", 0.0));
            StatItem("W KB/s", "%.0f", d.value("total_write_kbps", 0.0));
            StatItem("IOPS",   "%.0f", d.value("total_iops", 0.0));
            StatItem("Util%%", "%.1f", d.value("max_util_pct", 0.0));
            ImGui::NewLine();
            std::vector<std::vector<float>> sers = {
                st.disk_read.ordered(), st.disk_write.ordered()
            };
            PlotMultiLine("Disk", sers, {"R", "W"}, 0, 0, ImVec2(-1, MID_H - 72));
        }
        EndPanel();
    }

    float y2 = y1 + MID_H;

    // ── Row 3: Network + Load ──
    {
        float xL = vp->Pos.x;
        float xR = xL + PW + 2;

        // Network
        BeginPanel("Network", xL, y2, PW, LOW_H);
        if (st.has_data && st.latest.contains("network")) {
            auto& n = st.latest["network"];
            StatItem("RX kbps", "%.0f", n.value("total_rx_kbps", 0.0));
            StatItem("TX kbps", "%.0f", n.value("total_tx_kbps", 0.0));
            StatItem("RX pps",  "%.0f", n.value("total_rx_pps", 0.0));
            StatItem("TX pps",  "%.0f", n.value("total_tx_pps", 0.0));
            ImGui::NewLine();
            std::vector<std::vector<float>> sers = {
                st.net_rx.ordered(), st.net_tx.ordered()
            };
            PlotMultiLine("Net", sers, {"RX", "TX"}, 0, 0, ImVec2(-1, LOW_H - 72));
        }
        EndPanel();

        // Load + Thermal
        BeginPanel("Load & Thermal", xR, y2, PW, LOW_H);
        if (st.has_data && st.latest.contains("load")) {
            auto& l = st.latest["load"];
            StatItem("1m",    "%.2f", l.value("load1", 0.0));
            StatItem("5m",    "%.2f", l.value("load5", 0.0));
            StatItem("15m",   "%.2f", l.value("load15", 0.0));
            StatItem("Procs", "%.0f", l.value("total_procs", 0.0));
            ImGui::NewLine();
            // Thermal bar
            if (st.latest.contains("thermal")) {
                for (auto& z : st.latest["thermal"]) {
                    float t = z.value("temp", 0.0f);
                    std::string tp = z.value("type", "unknown");
                    ImGui::TextColored(thermal_color(t), "%4.1fC", t);
                    ImGui::SameLine();
                    ImGui::TextDisabled("%s", tp.c_str());
                    ImGui::SameLine();
                    ImGui::ProgressBar(ImClamp(t / 100.0f, 0.0f, 1.0f), ImVec2(80, 10), "");
                    ImGui::NewLine();
                }
            }
            std::vector<std::vector<float>> sers = {
                st.load1.ordered(), st.load5.ordered(), st.load15.ordered()
            };
            PlotMultiLine("Load", sers, {"1m", "5m", "15m"}, 0, 0,
                          ImVec2(-1, LOW_H - 32 - st.latest.value("thermal", json::array()).size() * 22.0f));
        }
        EndPanel();
    }

    float y3 = y2 + LOW_H;

    // ── BPF rows (only if enabled) ──
    if (!st.bpf_enabled) {
        BeginPanel("BPF Tracing", vp->Pos.x, y3, VW, BPF_H);
        PanelMsg("BPF disabled. Run: sudo ./monitor_server.py --bpf",
                 ImVec4(0.82f, 0.60f, 0.13f, 1.0f));
        EndPanel();
        return;
    }

    float xL = vp->Pos.x;
    float xR = xL + PW + 2;

    // Scheduler latency + Disk latency
    BeginPanel("Scheduler Latency (us) - BPF", xL, y3, PW, BPF_H);
    if (!st.bpf_cpu_ok)
        PanelMsg("BPF CPU probe not running", ImVec4(0.97f, 0.32f, 0.29f, 1.0f));
    else
        PlotHistogram("Scheduler Latency (us)", st.sched_hist, ImVec2(-1, BPF_H - 32));
    EndPanel();

    BeginPanel("Disk I/O Latency (us) - BPF", xR, y3, PW, BPF_H);
    if (!st.bpf_disk_ok)
        PanelMsg("BPF Disk probe not running", ImVec4(0.97f, 0.32f, 0.29f, 1.0f));
    else
        PlotHistogram("Disk I/O Latency (us)", st.disk_hist, ImVec2(-1, BPF_H - 32));
    EndPanel();

    float y4 = y3 + BPF_H;

    // Page alloc + Net packets
    BeginPanel("Page Alloc Rate (pages/s) - BPF", xL, y4, PW, BPF_H * 0.9f);
    if (!st.bpf_mem_ok)
        PanelMsg("BPF Mem probe not running", ImVec4(0.97f, 0.32f, 0.29f, 1.0f));
    else {
        std::vector<std::vector<float>> sers = {
            st.page_alloc.ordered(), st.page_free.ordered()
        };
        PlotMultiLine("Pages", sers, {"Alloc", "Free"}, 0, 0,
                      ImVec2(-1, BPF_H * 0.9f - 32));
    }
    EndPanel();

    BeginPanel("Network Packets (pkts/s) - BPF", xR, y4, PW, BPF_H * 0.9f);
    if (!st.bpf_net_ok)
        PanelMsg("BPF Net probe not running", ImVec4(0.97f, 0.32f, 0.29f, 1.0f));
    else {
        std::vector<std::vector<float>> sers = {
            st.bpf_tx_pkts.ordered(), st.bpf_rx_pkts.ordered()
        };
        PlotMultiLine("Net BPF", sers, {"TX", "RX"}, 0, 0,
                      ImVec2(-1, BPF_H * 0.9f - 32));
    }
    EndPanel();
}

// ─────────────────────────────────────────────────────────────
// ImGui style setup – dark theme matching web dashboard
// ─────────────────────────────────────────────────────────────
static void SetupStyle() {
    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowRounding    = 6;
    s.FrameRounding     = 4;
    s.GrabRounding      = 4;
    s.TabRounding       = 4;
    s.ScrollbarRounding = 6;
    s.WindowPadding     = ImVec2(12, 10);
    s.FramePadding      = ImVec2(6, 4);
    s.ItemSpacing       = ImVec2(10, 6);
    s.ItemInnerSpacing  = ImVec2(6, 4);

    ImVec4* colors = ImGui::GetStyle().Colors;
    colors[ImGuiCol_WindowBg]         = ImVec4(0.09f, 0.10f, 0.14f, 1.0f);
    colors[ImGuiCol_ChildBg]          = ImVec4(0.09f, 0.10f, 0.14f, 1.0f);
    colors[ImGuiCol_Border]           = ImVec4(0.19f, 0.21f, 0.25f, 1.0f);
    colors[ImGuiCol_FrameBg]          = ImVec4(0.12f, 0.14f, 0.18f, 1.0f);
    colors[ImGuiCol_FrameBgHovered]   = ImVec4(0.16f, 0.18f, 0.23f, 1.0f);
    colors[ImGuiCol_FrameBgActive]    = ImVec4(0.29f, 0.55f, 0.84f, 0.3f);
    colors[ImGuiCol_TitleBg]          = ImVec4(0.06f, 0.07f, 0.10f, 1.0f);
    colors[ImGuiCol_TitleBgActive]    = ImVec4(0.09f, 0.10f, 0.14f, 1.0f);
    colors[ImGuiCol_Header]           = ImVec4(0.16f, 0.18f, 0.23f, 0.8f);
    colors[ImGuiCol_HeaderHovered]    = ImVec4(0.19f, 0.22f, 0.28f, 0.8f);
    colors[ImGuiCol_HeaderActive]     = ImVec4(0.29f, 0.55f, 0.84f, 0.5f);
    colors[ImGuiCol_Button]           = ImVec4(0.16f, 0.18f, 0.23f, 1.0f);
    colors[ImGuiCol_ButtonHovered]    = ImVec4(0.22f, 0.25f, 0.32f, 1.0f);
    colors[ImGuiCol_ButtonActive]     = ImVec4(0.29f, 0.55f, 0.84f, 0.5f);
    colors[ImGuiCol_Tab]              = ImVec4(0.12f, 0.14f, 0.18f, 1.0f);
    colors[ImGuiCol_TabHovered]       = ImVec4(0.19f, 0.22f, 0.28f, 1.0f);
    colors[ImGuiCol_TabActive]        = ImVec4(0.19f, 0.21f, 0.25f, 1.0f);
    colors[ImGuiCol_PlotLines]        = ImVec4(0.35f, 0.58f, 1.0f, 1.0f);
    colors[ImGuiCol_PlotHistogram]    = ImVec4(0.35f, 0.58f, 1.0f, 0.6f);
    colors[ImGuiCol_Text]             = ImVec4(0.90f, 0.93f, 0.96f, 1.0f);
    colors[ImGuiCol_TextDisabled]     = ImVec4(0.55f, 0.58f, 0.62f, 1.0f);
}

// ─────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    AppState st;
    if (argc > 1) st.server_url = argv[1];

    // ── Init SDL2 ──
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER) != 0) {
        fprintf(stderr, "SDL_Init: %s\n", SDL_GetError());
        return 1;
    }

    const char* glsl_version = nullptr;

    // Try desktop OpenGL 3.0 first
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
    SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
    SDL_GL_SetAttribute(SDL_GL_DEPTH_SIZE, 24);

    SDL_Window* window = SDL_CreateWindow(
        "bpfscript - ImGui Monitor", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
        1440, 900,
        SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI);

    if (window) {
        glsl_version = "#version 130";
    } else {
        // Fallback to OpenGL ES 3.0 (ARM Mali GPU)
        SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_ES);
        SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
        SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
        window = SDL_CreateWindow(
            "bpfscript - ImGui Monitor", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
            1440, 900,
            SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI);
        glsl_version = "#version 300 es";

        if (!window) {
            // Last resort: GLES 2.0
            SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 2);
            SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
            window = SDL_CreateWindow(
                "bpfscript - ImGui Monitor", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
                1440, 900,
                SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI);
            glsl_version = "#version 100";
        }
    }

    if (!window) {
        fprintf(stderr, "SDL_CreateWindow: %s\n", SDL_GetError());
        SDL_Quit();
        return 1;
    }

    SDL_GLContext gl_ctx = SDL_GL_CreateContext(window);
    SDL_GL_MakeCurrent(window, gl_ctx);
    SDL_GL_SetSwapInterval(1);

    // ── Init ImGui ──
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = nullptr;

    SetupStyle();

    ImGui_ImplSDL2_InitForOpenGL(window, gl_ctx);
    ImGui_ImplOpenGL3_Init(glsl_version);

    // ── Start fetch thread ──
    std::atomic<bool> running{true};
    std::thread fetcher(fetch_thread, std::ref(running), std::ref(st));

    fprintf(stderr, "ImGui monitor started. Server: %s\n", st.server_url.c_str());
    fprintf(stderr, "GLSL version: %s\n", glsl_version);

    // ── Main loop ──
    while (running) {
        SDL_Event ev;
        while (SDL_PollEvent(&ev)) {
            ImGui_ImplSDL2_ProcessEvent(&ev);
            if (ev.type == SDL_QUIT) running = false;
            if (ev.type == SDL_KEYDOWN && ev.key.keysym.sym == SDLK_ESCAPE)
                running = false;
        }

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplSDL2_NewFrame();
        ImGui::NewFrame();

        RenderDashboard(st);

        ImGui::Render();
        glViewport(0, 0, (int)io.DisplaySize.x, (int)io.DisplaySize.y);
        glClearColor(0.05f, 0.07f, 0.10f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        SDL_GL_SwapWindow(window);

        SDL_Delay(16); // ~60 fps
    }

    // ── Cleanup ──
    running = false;
    fetcher.join();

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplSDL2_Shutdown();
    ImGui::DestroyContext();
    SDL_GL_DeleteContext(gl_ctx);
    SDL_DestroyWindow(window);
    SDL_Quit();

    return 0;
}
