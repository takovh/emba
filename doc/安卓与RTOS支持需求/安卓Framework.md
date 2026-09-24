安卓 **Framework（应用框架层）** 是 Android 系统中连接“应用程序”和“底层系统能力”的核心软件层。

简单说：**App 不需要自己直接管理屏幕、相机、网络、通知、窗口或权限；它通过 Framework 提供的 API 请求这些能力，Framework 再协调系统服务和底层硬件完成工作。**

## Android 大致分层

```text
应用层
  └─ 微信、浏览器、相机、你的 App

Android Framework（应用框架层）
  └─ Activity、Window、通知、权限、位置、包管理等系统能力

Android Runtime / Native Libraries
  └─ ART、SQLite、媒体编解码、图形库等

HAL / Linux Kernel
  └─ 硬件抽象层、驱动、CPU、内存、摄像头、Wi‑Fi 等硬件
```

## Framework 的主要作用

### 1. 给 App 提供统一开发接口

开发者通常通过 Java 或 Kotlin 调用 Android API，例如：

- `Activity`：一个界面或页面的生命周期管理
- `Service`：在后台执行任务
- `BroadcastReceiver`：接收系统事件，例如开机、网络变化、电量变化
- `ContentProvider`：在应用之间安全共享数据
- `NotificationManager`：发送通知
- `LocationManager`：获取定位
- `CameraManager`：使用相机
- `PackageManager`：查询已安装应用、权限和包信息

例如，App 调用通知 API：

```kotlin
notificationManager.notify(1, notification)
```

它不需要知道通知怎样显示到状态栏上；Framework 会把请求交给相关系统服务处理。

---

### 2. 管理应用的生命周期和任务

Framework 负责决定：

- 应用什么时候启动；
- 页面（Activity）什么时候创建、暂停、恢复、销毁；
- 后台 Service 是否允许继续运行；
- 内存不足时优先杀掉哪些进程；
- 多任务列表、返回栈如何组织。

比如用户从一个 App 切到另一个 App，原 App 通常不是立刻退出，而是进入后台暂停状态。这些过程由 Framework 中的系统服务协调。

---

### 3. 统一管理系统资源

手机硬件资源有限，Framework 需要协调多个 App 对资源的访问，例如：

- 摄像头通常不能被多个 App 随意同时独占；
- GPS、蓝牙、Wi‑Fi 的使用受权限和省电影响；
- 音频焦点需要在音乐、电话、导航之间切换；
- 屏幕亮度、旋转方向、窗口显示由系统统一管理；
- 内存、CPU 调度与后台执行受系统策略限制。

这避免了每个 App 直接操作硬件造成冲突或安全问题。

---

### 4. 提供安全与权限控制

Android Framework 是安全边界的重要组成部分。它会检查：

- 调用者是谁；
- 是否拥有相应权限；
- 是否允许跨应用访问数据；
- 是否符合前台/后台执行限制；
- 是否有能力调用敏感系统接口。

例如，一个普通 App 即使调用了相机或读取联系人相关接口，也必须在权限模型和系统策略允许的前提下才会成功。

---

### 5. 通过系统服务实现核心功能

Framework 中很多能力以 **System Service（系统服务）** 的形式存在。常见例子包括：

| 系统服务 | 主要职责 |
|---|---|
| Activity Manager | 管理应用进程、Activity 生命周期、任务栈 |
| Window Manager | 管理窗口、屏幕显示、触摸区域 |
| Package Manager | 管理 APK 安装、应用信息、权限 |
| Power Manager | 管理唤醒锁、省电、休眠 |
| Location Manager | 管理定位服务 |
| Notification Manager | 管理通知 |
| Connectivity Manager | 管理网络连接状态 |
| Sensor Manager | 管理加速度计、陀螺仪等传感器 |

应用调用 API 时，很多请求最终会通过 **Binder IPC**（Android 的进程间通信机制）发送给这些系统服务。

---

## 从固件分析角度理解

如果你在分析 Android 固件，常说的 “Framework” 也可能指系统镜像中的框架文件，例如：

```text
/system/framework/
```

其中常见文件有：

```text
framework.jar
services.jar
framework-res.apk
```

它们大致对应：

- **`framework.jar`**：Android 核心 API 与框架代码；
- **`services.jar`**：许多系统服务相关实现；
- **`framework-res.apk`**：系统级资源，例如字符串、主题、界面布局、权限定义等。

厂商往往会在这里加入定制功能，例如系统权限、设备管理接口、预装服务、主题、网络策略，甚至安全相关逻辑。因此它也是 Android ROM 和固件逆向分析中的重点区域。

## 一句话总结

**Android Framework 是 Android 的“系统能力调度中心和应用开发平台”：向 App 提供标准 API，统一管理界面、进程、权限、通知、硬件资源和系统服务，同时把 App 请求安全地传递到底层系统。**