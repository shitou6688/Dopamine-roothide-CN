# Dopamine-roothide 国内网络内核源 + GitHub Actions 打包

## 结论先说

不用给设备挂代理。构建机（GitHub Actions 的 macOS runner）替你完成所有境外网络请求，把结果塞进 IPA；设备端要么完全不联网，要么只连 Apple 在国内有缓存节点的 CDN。

> 本仓库：`https://github.com/shitou6688/Dopamine-roothide-CN`。工作流默认 `coverage=all`，索引覆盖所有支持越狱的机型与系统版本，普通签名安装的设备都不需要代理。构建链已在 Actions 跑通（macos-15 / Xcode 16.4），产物见 Actions → `Build Dopamine-roothide CN` 的 Artifacts。

## 全量覆盖（coverage=all，默认）

单设备索引每条都要下载 17 MB kernelcache 算 SHA-256，几千条会跑爆 CI。全量索引改用 **ZIP 中央目录**里的信息：文件名、压缩方式、offset、length、原始大小、以及**未压缩数据的 CRC32**。构建机对每个 IPSW 只读尾部 64 KB、中央目录、几十字节的 local header 和 BuildManifest.plist，并发探测即可；设备端 inflate 后用 CRC32 验真（zlib 已链接）。真实固件实测：18,620,103 字节内核，计算 CRC32 `0x98e5063d` 与索引一致。

设备清单来自 `api.ipsw.me/v4/devices`，按 `-versionSupportString` 的范围过滤（iOS/iPadOS 15.0–18.7.1，A12/A13 PPL 分支另含 26.0–26.0.1），逐设备取其所有仍可访问的 IPSW 直链。索引键仍是 `<hw.machine>|<kern.osversion>`，命中就完全不碰 `appledb.dev`；查不到才回落 `grab_images()`。

`coverage=single` 则退回旧的按 `targets.txt` 生成单设备索引（schema 1，带 SHA-256），也可同时产出该设备的完全离线包。

## 为什么原来必须挂代理

`Application/Dopamine/Jailbreak/DOEnvironmentManager.m` 的 `-accessibleKernelPath` 在**非 TrollStore 安装的普通签名 IPA** 里读不到系统 kernelcache，于是调用 `grab_images()`（闭源的 `libgrabkernel2.a`）。从该静态库里可读出它第一步请求：

```
https://api.appledb.dev/ios/main.json.xz    ← 约 72 MB 的第三方元数据，国内不稳定
https://api.appledb.dev/ios/%@;%@.json
```

拿到固件 URL 后，它再对 `updates.cdn-apple.com` 做 partial-zip，取 `BuildManifest.plist`、`kernelcache`、`sptm.im4p`、`txm.im4p`。也就是说：**固件本体走 Apple CDN，国内直连是通的**（实测返回 `206 Partial Content`，响应链经过国内缓存节点）；卡住的只有 AppleDB 那一步元数据。

## Relaxin 到底做了什么

Relaxin 并不是"换了个国内下载源"。它把 kernelcache 里能静态确定的偏移在构建机上提前算出来，压成 `Relaxin/Resources/KernelOffsets.plist`（971 个 `<机型>|<Build>` 条目，1.8 MB）。运行时 `RLXKernelCacheAcquisitionTask` 的优先级是：系统 kernelcache → app bundle → Documents → **查内置表（命中就直接 return，下载/拷贝/解析全跳过）** → 才回落 `grab_kernelcache_for_with_error`。

那张表存的是 Rocket 引擎的 `RocketStaticKernelProfile`，而 Dopamine 用的是 XPF 的 `xpf_construct_offset_dictionary()` 输出，两者键集合与结构不同，**plist 文件不能直接搬过来**。但架构可以照搬，而且 Dopamine 自己已经留好了口子：

```objc
// DOEnvironmentManager.m -accessibleKernelPath / -accessibleSPTMPath / -accessibleTXMPath
[NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"kernelcache"]  // 已内置就直接用
... @"sptm.img4" / @"txm.img4"
```

本方案就是把 Relaxin 的"内置表 + 命中跳过下载"补进 Dopamine，并额外把元数据解析提前到构建期。

## 两种产物

| 产物 | 设备端网络行为 | 适用 |
| --- | --- | --- |
| `Dopamine-roothide-CN-*.ipa/.tipa`（`coverage=all`） | 只向 `updates.cdn-apple.com` 发 3 个 HTTP Range 请求（约 17 MB），**不访问 appledb.dev** | **不限制设备**，所有支持越狱的 iPhone/iPad 普通签名安装都免代理 |
| 同名通用包（`coverage=single`） | 同上 | 只覆盖 `targets.txt` 里那一个 `<机型>|<Build>`，其余设备会回落原下载 |
| `*-OFFLINE-<机型>-<Build>.ipa/.tipa` | **零联网下载**，kernelcache / sptm.im4p / txm.im4p 已内置在 app bundle | 仅 `coverage=single` 产出，严格绑定文件名里的机型与 Build，不能跨机用 |

两者都保留原 `grab_images()` 作为最后回落，索引未命中或下载失败时行为与上游一致。

## 三步使用

1. **建仓库**（二选一，不用 Mac；本仓库已经建好，直接用可跳过此步）
   - A：新建一个空仓库，把本目录的 `.github/` 和 `Tools/` 原样放进去。工作流会自动克隆 `roothide/Dopamine-roothide` 的 `3.x` 分支再打补丁。仓库小、最省事。
   - B：Fork `roothide/Dopamine-roothide`，把 `.github/workflows/build-cn.yml` 和 `Tools/` 加到 3.x 分支。工作流直接用 fork 源码。

2. **选覆盖范围**：默认 `coverage=all`，**不用填任何机型**，跑完的通用包覆盖所有支持越狱的设备与系统版本。只有在要给自己那台出「完全离线包」时才改成 `coverage=single` 并编辑 `Tools/targets.txt`，写 `机型|系统Build`（例如 `iPhone15,3|21D61`）。
   - 机型：`ideviceinfo -k ProductType`，或爱思助手查看。
   - Build：设置 → 通用 → 关于本机，版本号下方括号里的编号。设备端查表键就是 `<hw.machine>|<kern.osversion>`，必须准确。
   - 也可以不编辑文件，直接在 Run workflow 界面填 `device` + `os_build`；解析不到固件时把完整 IPSW 直链填进 `firmware_url`。

3. **跑工作流**：Actions → `Build Dopamine-roothide CN` → Run workflow。
   - 全设备免代理：保持 `coverage=all`，`mode` 选 `index` 或 `both`（`both` 在全量模式下也只出通用包）。`workers` 默认 32，请求被限流就调小。全量索引要并发探测几千个 IPSW，构建时间比单设备版长。
   - 勾 `make_release` 可同时发到 Releases；否则只在 Artifacts 下载。
   - `coverage=all` + `mode=offline` 没有意义，工作流会直接报错退出。
   - 等效命令：`gh workflow run build-cn.yml -R shitou6688/Dopamine-roothide-CN -f coverage=all -f mode=index -f make_release=true`

产物是未签名 IPA / TIPA，用你原来的方式签名安装即可。IPA 与 TIPA 内容相同，仅扩展名不同（上游 Makefile 也是如此）。

## 换成自己的国内镜像（可选）

把设备端请求指向你自己的 OSS / COS / CDN，编辑生成的 `KernelIndex.plist`（或放进设备的 `Documents/KernelIndexOverride.plist`，无需重打包）：

```xml
<key>directURLs</key>
<dict>
    <key>kernel</key><array><string>https://your-cn-cdn.example/kernelcache-21D61</string></array>
    <key>sptm</key>  <array><string>https://your-cn-cdn.example/sptm-21D61.im4p</string></array>
    <key>txm</key>   <array><string>https://your-cn-cdn.example/txm-21D61.im4p</string></array>
</dict>
```

`directURLs` 指向**已解压好的完整文件**（不是 IPSW 内部片段），优先级高于 Range 路径。`firmwareURLs` 数组也可换成多个镜像地址，运行时会逐个重试并校验 SHA-256。

## 改动清单

| 文件 | 作用 |
| --- | --- |
| `.github/workflows/build-cn.yml` | macOS runner 全流程：装 THEOS/Procursus/trustcache → 打补丁 → 解析元数据 → gmake → 重打包 → 上传/发布 |
| `Tools/cn_kernel.py` | 远程 ZIP64 读取；`selftest / probe / index / fullindex / fetch / patch / pack` 七个子命令，仅标准库。`fullindex` 并发生成全设备 schema-2 索引 |
| `Tools/DO_CN_KernelSource.h` | 设备端运行时，全内联实现，`#import` 进 `DOEnvironmentManager.m` 即可；**不改 .xcodeproj**。同时兼容 schema 1（SHA-256）与 schema 2（CRC32） |
| `Tools/targets.txt` | 目标设备清单 |

源码补丁只动 `DOEnvironmentManager.m` 一个文件：加一行 `#import`；把 `-accessibleKernelPath` 的下载块换成"先查内置索引，失败回落 `grab_images`"；给 `-accessibleSPTMPath` / `-accessibleTXMPath` 各加一个 bundle 内 `.im4p` 查找（离线包用 IM4P 原名，与 `grab_images` 写进 Documents 的文件一致）。补丁幂等，重复执行不会叠加。工程里已经链接 `libz.tbd`，所以 raw-deflate 解压不需要新增链接。

## 已验证 / 未执行

已验证：远程 ZIP64 目录解析（合成包自测）、Apple CDN 的 206 Range、真实 11.5 GB 与 7.9 GB 两份 IPSW 的 kernelcache / sptm / txm 定位与 SHA-256、补丁在真实 3.x 源码上的精确 diff 与幂等性、**GitHub Actions 全量编译 + 重打包 + 产物上传**（单设备版 run `42813628737`，15 步全绿，产出 4 个 IPA/TIPA 共 244 MB）、全量索引小样本（真实固件 4 条）、**CRC32 端到端**（真实 18,620,103 字节内核 inflate 后计算 `0x98e5063d`，与 ZIP 中央目录一致）。

未执行：**真机越狱验证**（需要你自己的设备）。`coverage=all` 的全量构建由 CI 实测，跑完把结论补在这里。

工具链注意：runner 固定 `macos-15`、Xcode `16.4`。Xcode 26.6 / iPhoneOS26.5 SDK 下 Apple clang 21 的链接器会在 `watchdoghook.dylib` 段错误，`install_name_tool -delete_rpath` 也会报错；不要改成 `macos-latest`。另：`Install THEOS` 步骤不能提前创建非空的 `$THEOS`（安装脚本会误判为已安装并调用不存在的 `bin/update-theos`），SDK 用 `xz -dk` 显式解压。

其它限制：
- 索引按 `<机型>|<Build>` 固化，新系统版本发布后需重跑工作流刷新；未命中会静默回落到原下载路径（功能正常，只是那台设备仍需要代理）。
- 全量模式下，Apple 已下架的 IPSW 直链会 404，构建期自动跳过该条并在日志里列出 `skipped`，对应设备会回落原下载路径。
- 通过 TrollStore 装 TIPA 时，`isInstalledThroughTrollStore` 为真，上游本来就直接读系统 kernelcache，不存在下载问题，本补丁对这条路径无副作用。
- 单设备模式下旧 IPSW 若被下架，用 `firmware_url` 指定仍可访问的 OTA/IPSW 直链。
