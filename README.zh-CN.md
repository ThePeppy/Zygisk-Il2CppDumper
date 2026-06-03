# Zygisk-Il2CppDumper
Zygisk版Il2CppDumper，在游戏运行时dump il2cpp数据，可以绕过保护，加密以及混淆。

## 如何食用
1. 安装[Magisk](https://github.com/topjohnwu/Magisk) v24以上版本并开启Zygisk
2. 生成模块
   - GitHub Actions
      1. Fork这个项目
      2. 在你fork的项目中选择**Actions**选项卡
      3. 在左边的侧边栏中，单击**Build**
      4. 选择**Run workflow**
      5. 输入游戏包名并点击**Run workflow**
      6. 等待操作完成并下载
   - Android Studio
      1. 下载源码
      2. 编辑`game.h`, 修改`GamePackageName`为游戏包名
      3. 使用Android Studio运行gradle任务`:module:assembleRelease`编译，zip包会生成在`out`文件夹下
3. 在Magisk里安装模块
4. 启动游戏，会在`/data/data/GamePackageName/files/`目录下生成旧路径兼容用的`dump.cs`
5. 同时会在`/data/data/GamePackageName/files/Il2CppDumper/`目录下生成更接近桌面版的运行时输出：
   - `dump.cs`
   - `script.json`
   - `stringliteral.json`（运行时 API 暂不导出字符串字面量，所以当前为空数组）
   - `global-metadata.dat`（如果能在内存中找到解密后的 metadata）
   - `metadata_dump_status.txt`（未找到 metadata 时生成）
   - `il2cpp.h`（仅用于 IDA/Ghidra 解析基础函数签名，不包含完整结构体布局）
   - `ida_py3.py`

## 关于 IDA 恢复
`dump.cs` 只适合阅读类型、字段和方法声明；如果要在 IDA 里快速恢复函数名，请优先使用`Il2CppDumper/script.json`配合`ida_py3.py`导入。完整的`DummyDll/`和带字段布局的`il2cpp.h`仍然依赖`global-metadata.dat`和`libil2cpp.so`的离线解析，建议用桌面版 Il2CppDumper 继续生成。

## 关于 metadata dump
模块会扫描进程可读内存，寻找`0xFAB11BAF`开头且 header 布局校验通过的解密后 metadata，并写出为`global-metadata.dat`。如果游戏把 metadata 解密成非标准结构、加载后立即擦除，或需要在自定义解密函数返回前截获 buffer，本模块会生成`metadata_dump_status.txt`说明未找到。
