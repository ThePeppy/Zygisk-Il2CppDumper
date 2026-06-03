# Zygisk-Il2CppDumper
Il2CppDumper with Zygisk, dump il2cpp data at runtime, can bypass protection, encryption and obfuscation.

中文说明请戳[这里](README.zh-CN.md)

## How to use
1. Install [Magisk](https://github.com/topjohnwu/Magisk) v24 or later and enable Zygisk
2. Build module
   - GitHub Actions
      1. Fork this repo
      2. Go to the **Actions** tab in your forked repo
      3. In the left sidebar, click the **Build** workflow.
      4. Above the list of workflow runs, select **Run workflow**
      5. Input the game package name and click **Run workflow**
      6. Wait for the action to complete and download the artifact
   - Android Studio
      1. Download the source code
      2. Edit `game.h`, modify `GamePackageName` to the game package name
      3. Use Android Studio to run the gradle task `:module:assembleRelease` to compile, the zip package will be generated in the `out` folder
3. Install module in Magisk
4. Start the game. A legacy-compatible `dump.cs` will be generated in the `/data/data/GamePackageName/files/` directory.
5. Runtime output closer to desktop Il2CppDumper will also be generated in `/data/data/GamePackageName/files/Il2CppDumper/`:
   - `dump.cs`
   - `script.json`
   - `stringliteral.json` (currently an empty array because the runtime API path does not export string literals)
   - `il2cpp.h` (a minimal signature parser shim, not a full structure-layout header)
   - `ida_py3.py`

## IDA usage
`dump.cs` is useful for reading types, fields, and method declarations. For fast function-name recovery in IDA, import `Il2CppDumper/script.json` with `ida_py3.py`. Full `DummyDll/` output and a structure-rich `il2cpp.h` still require offline parsing with `global-metadata.dat` and `libil2cpp.so` via desktop Il2CppDumper.
