# Dopamine-roothide 国内网络内核源 + GitHub Actions 打包

## 结论先说

不用给设备挂代理。构建机（GitHub Actions 的 macOS runner）替你完成所有境外网络请求，把结果塞进 IPA；设备端要么完全不联网，要么只连 Apple 在国内有缓存节点的 CDN。

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
| `Dopamine-roothide-CN-*.ipa/.tipa` | 只向 `updates.cdn-apple.com` 发 3 个 HTTP Range 请求（约 17 MB），**不访问 appledb.dev** | 通用包，可一次覆盖多台设备/系统版本 |
| `*-OFFLINE-<机型>-<Build>.ipa/.tipa` | **零联网下载**，kernelcache / sptm.im4p / txm.im4p 已内置在 app bundle | 只给自己那台机用，最彻底 |

两者都保留原 `grab_images()` 作为最后回落，索引未命中或下载失败时行为与上游一致。

## 三步使用

1. **建仓库**（二选一，不用 Mac）
   - A：新建一个空仓库，把本目录的 `.github/` 和 `Tools/` 原样放进去。工作流会自动克隆 `roothide/Dopamine-roothide` 的 `3.x` 分支再打补丁。仓库小、最省事。
   - B：Fork `roothide/Dopamine-roothide`，把 `.github/workflows/build-cn.yml` 和 `Tools/` 加到 3.x 分支。工作流直接用 fork 源码。

2. **填目标**：编辑 `Tools/targets.txt`，写自己的 `机型|系统Build`，例如 `iPhone15,3|21D61`。
   - 机型：`ideviceinfo -k ProductType`，或爱思助手查看。
   - Build：设置 → 通用 → 关于本机，版本号下方括号里的编号。设备端查表键就是 `<hw.machine>|<kern.osversion>`，必须准确。
   - 也可以不编辑文件，直接在 Run workflow 界面填 `device` + `os_build`；解析不到固件时把完整 IPSW 直链填进 `firmware_url`。

3. **跑工作流**：Actions → `Build Dopamine-roothide CN` → Run workflow，`mode` 选 `both`（默认）。跑完在 Artifacts 下载，或勾选 `make_release` 直接发到 Releases。

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
| `Tools/cn_kernel.py` | 远程 ZIP64 读取、`selftest / probe / index / fetch / patch / pack` 六个子命令，仅标准库 |
| `Tools/DO_CN_KernelSource.h` | 设备端运行时，全内联实现，`#import` 进 `DOEnvironmentManager.m` 即可；**不改 .xcodeproj** |
| `Tools/targets.txt` | 目标设备清单 |

源码补丁只动 `DOEnvironmentManager.m` 一个文件：加一行 `#import`；把 `-accessibleKernelPath` 的下载块换成"先查内置索引，失败回落 `grab_images`"；给 `-accessibleSPTMPath` / `-accessibleTXMPath` 各加一个 bundle 内 `.im4p` 查找（离线包用 IM4P 原名，与 `grab_images` 写进 Documents 的文件一致）。补丁幂等，重复执行不会叠加。工程里已经链接 `libz.tbd`，所以 raw-deflate 解压不需要新增链接。

## 已验证 / 未执行

已验证：远程 ZIP64 目录解析（合成包自测）、Apple CDN 的 206 Range、真实 11.5 GB 与 7.9 GB 两份 IPSW 的 kernelcache / sptm / txm 定位与 SHA-256、`KernelIndex.plist` 生成、补丁在真实 3.x 源码上的精确 diff 与幂等性、工作流 YAML 结构。

未执行：**GitHub Actions 全量编译和真机越狱验证**（当前环境是 Windows，没有 macOS/Xcode）。你跑一次工作流即可验证；若 `gmake` 阶段报错，优先看 Xcode 版本与 `iPhoneOS16.5.sdk` 下载那一步，与上游官方 `main.yml` 行为一致。

其它限制：
- 索引按 build 固化，新系统版本发布后需重跑工作流刷新；未命中会静默回落到原下载路径（功能正常，只是仍需要代理）。
- 通过 TrollStore 装 TIPA 时，`isInstalledThroughTrollStore` 为真，上游本来就直接读系统 kernelcache，不存在下载问题，本补丁对这条路径无副作用。
- 旧版本 IPSW 若被 Apple 下架导致直链 404，用 `firmware_url` 指定仍可访问的 OTA/IPSW 直链。
