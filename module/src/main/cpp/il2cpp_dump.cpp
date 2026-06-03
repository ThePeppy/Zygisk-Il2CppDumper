//
// Created by Perfare on 2020/7/4.
//

#include "il2cpp_dump.h"
#include <dlfcn.h>
#include <cstdlib>
#include <cstring>
#include <cinttypes>
#include <cerrno>
#include <algorithm>
#include <cctype>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>
#include "xdl.h"
#include "log.h"
#include "il2cpp-tabledefs.h"
#include "il2cpp-class.h"

#define DO_API(r, n, p) r (*n) p

#include "il2cpp-api-functions.h"

#undef DO_API

static uint64_t il2cpp_base = 0;

bool _il2cpp_type_is_byref(const Il2CppType *type);

struct ScriptMethodOutput {
    uint64_t address;
    std::string name;
    std::string signature;
    std::string typeSignature;
};

struct DumpCollector {
    std::vector<ScriptMethodOutput> scriptMethods;
    std::vector<uint64_t> addresses;
};

const char *safe_cstr(const char *value) {
    return value ? value : "";
}

bool ensure_dir(const std::string &path) {
    if (path.empty()) {
        return false;
    }
    if (mkdir(path.c_str(), 0770) == 0 || errno == EEXIST) {
        return true;
    }
    LOGE("mkdir failed: %s, errno: %d", path.c_str(), errno);
    return false;
}

std::string json_escape(const std::string &value) {
    std::stringstream outPut;
    for (unsigned char c: value) {
        switch (c) {
            case '\"':
                outPut << "\\\"";
                break;
            case '\\':
                outPut << "\\\\";
                break;
            case '\b':
                outPut << "\\b";
                break;
            case '\f':
                outPut << "\\f";
                break;
            case '\n':
                outPut << "\\n";
                break;
            case '\r':
                outPut << "\\r";
                break;
            case '\t':
                outPut << "\\t";
                break;
            default:
                if (c < 0x20) {
                    char buffer[7];
                    snprintf(buffer, sizeof(buffer), "\\u%04x", c);
                    outPut << buffer;
                } else {
                    outPut << c;
                }
                break;
        }
    }
    return outPut.str();
}

bool is_c_keyword(const std::string &value) {
    static const char *keywords[] = {
            "auto", "break", "case", "char", "const", "continue", "default", "do",
            "double", "else", "enum", "extern", "float", "for", "goto", "if",
            "inline", "int", "long", "register", "restrict", "return", "short",
            "signed", "sizeof", "static", "struct", "switch", "typedef", "union",
            "unsigned", "void", "volatile", "while", "_Bool"
    };
    for (auto keyword: keywords) {
        if (value == keyword) {
            return true;
        }
    }
    return false;
}

std::string fix_c_name(const std::string &value) {
    std::string fixedName;
    fixedName.reserve(value.size() + 1);
    for (unsigned char c: value) {
        if (std::isalnum(c) || c == '_') {
            fixedName.push_back(static_cast<char>(c));
        } else {
            fixedName.push_back('_');
        }
    }
    if (fixedName.empty()) {
        fixedName = "_";
    }
    if (std::isdigit(static_cast<unsigned char>(fixedName[0])) || is_c_keyword(fixedName)) {
        fixedName.insert(fixedName.begin(), '_');
    }
    return fixedName;
}

std::string get_class_script_name(Il2CppClass *klass) {
    std::vector<std::string> names;
    auto current = klass;
    while (current) {
        names.emplace_back(safe_cstr(il2cpp_class_get_name(current)));
        current = il2cpp_class_get_declaring_type ? il2cpp_class_get_declaring_type(current) : nullptr;
    }
    std::reverse(names.begin(), names.end());

    std::stringstream outPut;
    auto namespaze = safe_cstr(il2cpp_class_get_namespace(klass));
    if (strlen(namespaze) > 0) {
        outPut << namespaze << ".";
    }
    for (size_t i = 0; i < names.size(); ++i) {
        if (i > 0) {
            outPut << ".";
        }
        outPut << names[i];
    }
    return outPut.str();
}

std::string get_c_type_name(const Il2CppType *type) {
    if (!type) {
        return "void*";
    }

    std::string typeName;
    switch (type->type) {
        case IL2CPP_TYPE_VOID:
            typeName = "void";
            break;
        case IL2CPP_TYPE_BOOLEAN:
            typeName = "bool";
            break;
        case IL2CPP_TYPE_CHAR:
            typeName = "unsigned short";
            break;
        case IL2CPP_TYPE_I1:
            typeName = "signed char";
            break;
        case IL2CPP_TYPE_U1:
            typeName = "unsigned char";
            break;
        case IL2CPP_TYPE_I2:
            typeName = "short";
            break;
        case IL2CPP_TYPE_U2:
            typeName = "unsigned short";
            break;
        case IL2CPP_TYPE_I4:
            typeName = "int";
            break;
        case IL2CPP_TYPE_U4:
            typeName = "unsigned int";
            break;
        case IL2CPP_TYPE_I8:
            typeName = "long long";
            break;
        case IL2CPP_TYPE_U8:
            typeName = "unsigned long long";
            break;
        case IL2CPP_TYPE_R4:
            typeName = "float";
            break;
        case IL2CPP_TYPE_R8:
            typeName = "double";
            break;
        case IL2CPP_TYPE_I:
            typeName = "long";
            break;
        case IL2CPP_TYPE_U:
            typeName = "unsigned long";
            break;
        case IL2CPP_TYPE_PTR:
        case IL2CPP_TYPE_STRING:
        case IL2CPP_TYPE_VALUETYPE:
        case IL2CPP_TYPE_CLASS:
        case IL2CPP_TYPE_VAR:
        case IL2CPP_TYPE_ARRAY:
        case IL2CPP_TYPE_GENERICINST:
        case IL2CPP_TYPE_TYPEDBYREF:
        case IL2CPP_TYPE_OBJECT:
        case IL2CPP_TYPE_SZARRAY:
        case IL2CPP_TYPE_MVAR:
        default:
            typeName = "void*";
            break;
    }

    // 运行时 API 无法稳定还原完整结构体名，复杂类型统一写成指针，保证 IDA 能先应用函数原型。
    if (_il2cpp_type_is_byref(type) && typeName != "void") {
        typeName += "*";
    }
    return typeName;
}

char get_type_signature_char(const Il2CppType *type) {
    if (!type || _il2cpp_type_is_byref(type)) {
        return 'i';
    }
    switch (type->type) {
        case IL2CPP_TYPE_VOID:
            return 'v';
        case IL2CPP_TYPE_I8:
        case IL2CPP_TYPE_U8:
            return 'j';
        case IL2CPP_TYPE_R4:
            return 'f';
        case IL2CPP_TYPE_R8:
            return 'd';
        default:
            return 'i';
    }
}

void collect_script_method(Il2CppClass *klass, const MethodInfo *method, uint32_t flags,
                           DumpCollector *collector) {
    if (!collector || !method || !method->methodPointer || il2cpp_base == 0) {
        return;
    }

    auto methodAddress = reinterpret_cast<uint64_t>(method->methodPointer);
    if (methodAddress < il2cpp_base) {
        return;
    }

    ScriptMethodOutput scriptMethod{};
    scriptMethod.address = methodAddress - il2cpp_base;
    scriptMethod.name = get_class_script_name(klass) + "$$" + safe_cstr(il2cpp_method_get_name(method));

    std::vector<std::string> parameterStrs;
    std::stringstream typeSignature;
    auto returnType = il2cpp_method_get_return_type(method);
    typeSignature << get_type_signature_char(returnType);

    if ((flags & METHOD_ATTRIBUTE_STATIC) == 0) {
        parameterStrs.emplace_back("void* __this");
        typeSignature << 'i';
    }

    auto paramCount = il2cpp_method_get_param_count(method);
    for (int i = 0; i < paramCount; ++i) {
        auto param = il2cpp_method_get_param(method, i);
        auto paramName = safe_cstr(il2cpp_method_get_param_name(method, i));
        std::stringstream parameter;
        parameter << get_c_type_name(param) << " ";
        if (strlen(paramName) > 0) {
            parameter << fix_c_name(paramName);
        } else {
            parameter << "param_" << i;
        }
        parameterStrs.emplace_back(parameter.str());
        typeSignature << get_type_signature_char(param);
    }

    parameterStrs.emplace_back("const MethodInfo* method");
    typeSignature << 'i';

    std::stringstream signature;
    signature << get_c_type_name(returnType) << " " << fix_c_name(scriptMethod.name) << " (";
    for (size_t i = 0; i < parameterStrs.size(); ++i) {
        if (i > 0) {
            signature << ", ";
        }
        signature << parameterStrs[i];
    }
    signature << ");";
    scriptMethod.signature = signature.str();
    scriptMethod.typeSignature = typeSignature.str();

    collector->scriptMethods.emplace_back(scriptMethod);
    collector->addresses.emplace_back(scriptMethod.address);
}

void write_script_json(const std::string &path, DumpCollector &collector) {
    std::sort(collector.addresses.begin(), collector.addresses.end());
    collector.addresses.erase(std::unique(collector.addresses.begin(), collector.addresses.end()),
                              collector.addresses.end());

    std::ofstream outStream(path);
    outStream << "{\n";
    outStream << "  \"ScriptMethod\": [\n";
    for (size_t i = 0; i < collector.scriptMethods.size(); ++i) {
        const auto &method = collector.scriptMethods[i];
        outStream << "    {\n";
        outStream << "      \"Address\": " << std::dec << method.address << ",\n";
        outStream << "      \"Name\": \"" << json_escape(method.name) << "\",\n";
        outStream << "      \"Signature\": \"" << json_escape(method.signature) << "\",\n";
        outStream << "      \"TypeSignature\": \"" << json_escape(method.typeSignature) << "\"\n";
        outStream << "    }";
        if (i + 1 < collector.scriptMethods.size()) {
            outStream << ",";
        }
        outStream << "\n";
    }
    outStream << "  ],\n";
    outStream << "  \"ScriptString\": [],\n";
    outStream << "  \"ScriptMetadata\": [],\n";
    outStream << "  \"ScriptMetadataMethod\": [],\n";
    outStream << "  \"Addresses\": [\n";
    for (size_t i = 0; i < collector.addresses.size(); ++i) {
        outStream << "    " << std::dec << collector.addresses[i];
        if (i + 1 < collector.addresses.size()) {
            outStream << ",";
        }
        outStream << "\n";
    }
    outStream << "  ]\n";
    outStream << "}\n";
}

void write_text_file(const std::string &path, const std::string &content) {
    std::ofstream outStream(path);
    outStream << content;
}

void init_il2cpp_api(void *handle) {
#define DO_API(r, n, p) {                      \
    n = (r (*) p)xdl_sym(handle, #n, nullptr); \
    if(!n) {                                   \
        LOGW("api not found %s", #n);          \
    }                                          \
}

#include "il2cpp-api-functions.h"

#undef DO_API
}

std::string get_method_modifier(uint32_t flags) {
    std::stringstream outPut;
    auto access = flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK;
    switch (access) {
        case METHOD_ATTRIBUTE_PRIVATE:
            outPut << "private ";
            break;
        case METHOD_ATTRIBUTE_PUBLIC:
            outPut << "public ";
            break;
        case METHOD_ATTRIBUTE_FAMILY:
            outPut << "protected ";
            break;
        case METHOD_ATTRIBUTE_ASSEM:
        case METHOD_ATTRIBUTE_FAM_AND_ASSEM:
            outPut << "internal ";
            break;
        case METHOD_ATTRIBUTE_FAM_OR_ASSEM:
            outPut << "protected internal ";
            break;
    }
    if (flags & METHOD_ATTRIBUTE_STATIC) {
        outPut << "static ";
    }
    if (flags & METHOD_ATTRIBUTE_ABSTRACT) {
        outPut << "abstract ";
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT) {
            outPut << "override ";
        }
    } else if (flags & METHOD_ATTRIBUTE_FINAL) {
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT) {
            outPut << "sealed override ";
        }
    } else if (flags & METHOD_ATTRIBUTE_VIRTUAL) {
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_NEW_SLOT) {
            outPut << "virtual ";
        } else {
            outPut << "override ";
        }
    }
    if (flags & METHOD_ATTRIBUTE_PINVOKE_IMPL) {
        outPut << "extern ";
    }
    return outPut.str();
}

bool _il2cpp_type_is_byref(const Il2CppType *type) {
    auto byref = type->byref;
    if (il2cpp_type_is_byref) {
        byref = il2cpp_type_is_byref(type);
    }
    return byref;
}

std::string dump_method(Il2CppClass *klass, DumpCollector *collector) {
    std::stringstream outPut;
    outPut << "\n\t// Methods\n";
    void *iter = nullptr;
    while (auto method = il2cpp_class_get_methods(klass, &iter)) {
        //TODO attribute
        if (method->methodPointer) {
            outPut << "\t// RVA: 0x";
            outPut << std::hex << (uint64_t) method->methodPointer - il2cpp_base;
            outPut << " VA: 0x";
            outPut << std::hex << (uint64_t) method->methodPointer;
        } else {
            outPut << "\t// RVA: 0x VA: 0x0";
        }
        /*if (method->slot != 65535) {
            outPut << " Slot: " << std::dec << method->slot;
        }*/
        outPut << "\n\t";
        uint32_t iflags = 0;
        auto flags = il2cpp_method_get_flags(method, &iflags);
        collect_script_method(klass, method, flags, collector);
        outPut << get_method_modifier(flags);
        //TODO genericContainerIndex
        auto return_type = il2cpp_method_get_return_type(method);
        if (_il2cpp_type_is_byref(return_type)) {
            outPut << "ref ";
        }
        auto return_class = il2cpp_class_from_type(return_type);
        outPut << il2cpp_class_get_name(return_class) << " " << il2cpp_method_get_name(method)
               << "(";
        auto param_count = il2cpp_method_get_param_count(method);
        for (int i = 0; i < param_count; ++i) {
            auto param = il2cpp_method_get_param(method, i);
            auto attrs = param->attrs;
            if (_il2cpp_type_is_byref(param)) {
                if (attrs & PARAM_ATTRIBUTE_OUT && !(attrs & PARAM_ATTRIBUTE_IN)) {
                    outPut << "out ";
                } else if (attrs & PARAM_ATTRIBUTE_IN && !(attrs & PARAM_ATTRIBUTE_OUT)) {
                    outPut << "in ";
                } else {
                    outPut << "ref ";
                }
            } else {
                if (attrs & PARAM_ATTRIBUTE_IN) {
                    outPut << "[In] ";
                }
                if (attrs & PARAM_ATTRIBUTE_OUT) {
                    outPut << "[Out] ";
                }
            }
            auto parameter_class = il2cpp_class_from_type(param);
            outPut << il2cpp_class_get_name(parameter_class) << " "
                   << il2cpp_method_get_param_name(method, i);
            outPut << ", ";
        }
        if (param_count > 0) {
            outPut.seekp(-2, outPut.cur);
        }
        outPut << ") { }\n";
        //TODO GenericInstMethod
    }
    return outPut.str();
}

std::string dump_property(Il2CppClass *klass) {
    std::stringstream outPut;
    outPut << "\n\t// Properties\n";
    void *iter = nullptr;
    while (auto prop_const = il2cpp_class_get_properties(klass, &iter)) {
        //TODO attribute
        auto prop = const_cast<PropertyInfo *>(prop_const);
        auto get = il2cpp_property_get_get_method(prop);
        auto set = il2cpp_property_get_set_method(prop);
        auto prop_name = il2cpp_property_get_name(prop);
        outPut << "\t";
        Il2CppClass *prop_class = nullptr;
        uint32_t iflags = 0;
        if (get) {
            outPut << get_method_modifier(il2cpp_method_get_flags(get, &iflags));
            prop_class = il2cpp_class_from_type(il2cpp_method_get_return_type(get));
        } else if (set) {
            outPut << get_method_modifier(il2cpp_method_get_flags(set, &iflags));
            auto param = il2cpp_method_get_param(set, 0);
            prop_class = il2cpp_class_from_type(param);
        }
        if (prop_class) {
            outPut << il2cpp_class_get_name(prop_class) << " " << prop_name << " { ";
            if (get) {
                outPut << "get; ";
            }
            if (set) {
                outPut << "set; ";
            }
            outPut << "}\n";
        } else {
            if (prop_name) {
                outPut << " // unknown property " << prop_name;
            }
        }
    }
    return outPut.str();
}

std::string dump_field(Il2CppClass *klass) {
    std::stringstream outPut;
    outPut << "\n\t// Fields\n";
    auto is_enum = il2cpp_class_is_enum(klass);
    void *iter = nullptr;
    while (auto field = il2cpp_class_get_fields(klass, &iter)) {
        //TODO attribute
        outPut << "\t";
        auto attrs = il2cpp_field_get_flags(field);
        auto access = attrs & FIELD_ATTRIBUTE_FIELD_ACCESS_MASK;
        switch (access) {
            case FIELD_ATTRIBUTE_PRIVATE:
                outPut << "private ";
                break;
            case FIELD_ATTRIBUTE_PUBLIC:
                outPut << "public ";
                break;
            case FIELD_ATTRIBUTE_FAMILY:
                outPut << "protected ";
                break;
            case FIELD_ATTRIBUTE_ASSEMBLY:
            case FIELD_ATTRIBUTE_FAM_AND_ASSEM:
                outPut << "internal ";
                break;
            case FIELD_ATTRIBUTE_FAM_OR_ASSEM:
                outPut << "protected internal ";
                break;
        }
        if (attrs & FIELD_ATTRIBUTE_LITERAL) {
            outPut << "const ";
        } else {
            if (attrs & FIELD_ATTRIBUTE_STATIC) {
                outPut << "static ";
            }
            if (attrs & FIELD_ATTRIBUTE_INIT_ONLY) {
                outPut << "readonly ";
            }
        }
        auto field_type = il2cpp_field_get_type(field);
        auto field_class = il2cpp_class_from_type(field_type);
        outPut << il2cpp_class_get_name(field_class) << " " << il2cpp_field_get_name(field);
        //TODO 获取构造函数初始化后的字段值
        if (attrs & FIELD_ATTRIBUTE_LITERAL && is_enum) {
            uint64_t val = 0;
            il2cpp_field_static_get_value(field, &val);
            outPut << " = " << std::dec << val;
        }
        outPut << "; // 0x" << std::hex << il2cpp_field_get_offset(field) << "\n";
    }
    return outPut.str();
}

std::string dump_type(const Il2CppType *type, DumpCollector *collector) {
    std::stringstream outPut;
    auto *klass = il2cpp_class_from_type(type);
    outPut << "\n// Namespace: " << il2cpp_class_get_namespace(klass) << "\n";
    auto flags = il2cpp_class_get_flags(klass);
    if (flags & TYPE_ATTRIBUTE_SERIALIZABLE) {
        outPut << "[Serializable]\n";
    }
    //TODO attribute
    auto is_valuetype = il2cpp_class_is_valuetype(klass);
    auto is_enum = il2cpp_class_is_enum(klass);
    auto visibility = flags & TYPE_ATTRIBUTE_VISIBILITY_MASK;
    switch (visibility) {
        case TYPE_ATTRIBUTE_PUBLIC:
        case TYPE_ATTRIBUTE_NESTED_PUBLIC:
            outPut << "public ";
            break;
        case TYPE_ATTRIBUTE_NOT_PUBLIC:
        case TYPE_ATTRIBUTE_NESTED_FAM_AND_ASSEM:
        case TYPE_ATTRIBUTE_NESTED_ASSEMBLY:
            outPut << "internal ";
            break;
        case TYPE_ATTRIBUTE_NESTED_PRIVATE:
            outPut << "private ";
            break;
        case TYPE_ATTRIBUTE_NESTED_FAMILY:
            outPut << "protected ";
            break;
        case TYPE_ATTRIBUTE_NESTED_FAM_OR_ASSEM:
            outPut << "protected internal ";
            break;
    }
    if (flags & TYPE_ATTRIBUTE_ABSTRACT && flags & TYPE_ATTRIBUTE_SEALED) {
        outPut << "static ";
    } else if (!(flags & TYPE_ATTRIBUTE_INTERFACE) && flags & TYPE_ATTRIBUTE_ABSTRACT) {
        outPut << "abstract ";
    } else if (!is_valuetype && !is_enum && flags & TYPE_ATTRIBUTE_SEALED) {
        outPut << "sealed ";
    }
    if (flags & TYPE_ATTRIBUTE_INTERFACE) {
        outPut << "interface ";
    } else if (is_enum) {
        outPut << "enum ";
    } else if (is_valuetype) {
        outPut << "struct ";
    } else {
        outPut << "class ";
    }
    outPut << il2cpp_class_get_name(klass); //TODO genericContainerIndex
    std::vector<std::string> extends;
    auto parent = il2cpp_class_get_parent(klass);
    if (!is_valuetype && !is_enum && parent) {
        auto parent_type = il2cpp_class_get_type(parent);
        if (parent_type->type != IL2CPP_TYPE_OBJECT) {
            extends.emplace_back(il2cpp_class_get_name(parent));
        }
    }
    void *iter = nullptr;
    while (auto itf = il2cpp_class_get_interfaces(klass, &iter)) {
        extends.emplace_back(il2cpp_class_get_name(itf));
    }
    if (!extends.empty()) {
        outPut << " : " << extends[0];
        for (int i = 1; i < extends.size(); ++i) {
            outPut << ", " << extends[i];
        }
    }
    outPut << "\n{";
    outPut << dump_field(klass);
    outPut << dump_property(klass);
    outPut << dump_method(klass, collector);
    //TODO EventInfo
    outPut << "}\n";
    return outPut.str();
}

void il2cpp_api_init(void *handle) {
    LOGI("il2cpp_handle: %p", handle);
    init_il2cpp_api(handle);
    if (il2cpp_domain_get_assemblies) {
        Dl_info dlInfo;
        if (dladdr((void *) il2cpp_domain_get_assemblies, &dlInfo)) {
            il2cpp_base = reinterpret_cast<uint64_t>(dlInfo.dli_fbase);
        }
        LOGI("il2cpp_base: %" PRIx64"", il2cpp_base);
    } else {
        LOGE("Failed to initialize il2cpp api.");
        return;
    }
    while (!il2cpp_is_vm_thread(nullptr)) {
        LOGI("Waiting for il2cpp_init...");
        sleep(1);
    }
    auto domain = il2cpp_domain_get();
    il2cpp_thread_attach(domain);
}

void il2cpp_dump(const char *outDir) {
    LOGI("dumping...");
    size_t size;
    auto domain = il2cpp_domain_get();
    auto assemblies = il2cpp_domain_get_assemblies(domain, &size);
    std::stringstream imageOutput;
    for (int i = 0; i < size; ++i) {
        auto image = il2cpp_assembly_get_image(assemblies[i]);
        imageOutput << "// Image " << i << ": " << il2cpp_image_get_name(image) << "\n";
    }
    std::vector<std::string> outPuts;
    DumpCollector collector;
    if (il2cpp_image_get_class) {
        LOGI("Version greater than 2018.3");
        //使用il2cpp_image_get_class
        for (int i = 0; i < size; ++i) {
            auto image = il2cpp_assembly_get_image(assemblies[i]);
            std::stringstream imageStr;
            imageStr << "\n// Dll : " << il2cpp_image_get_name(image);
            auto classCount = il2cpp_image_get_class_count(image);
            for (int j = 0; j < classCount; ++j) {
                auto klass = il2cpp_image_get_class(image, j);
                auto type = il2cpp_class_get_type(const_cast<Il2CppClass *>(klass));
                //LOGD("type name : %s", il2cpp_type_get_name(type));
                auto outPut = imageStr.str() + dump_type(type, &collector);
                outPuts.push_back(outPut);
            }
        }
    } else {
        LOGI("Version less than 2018.3");
        //使用反射
        auto corlib = il2cpp_get_corlib();
        auto assemblyClass = il2cpp_class_from_name(corlib, "System.Reflection", "Assembly");
        auto assemblyLoad = il2cpp_class_get_method_from_name(assemblyClass, "Load", 1);
        auto assemblyGetTypes = il2cpp_class_get_method_from_name(assemblyClass, "GetTypes", 0);
        if (assemblyLoad && assemblyLoad->methodPointer) {
            LOGI("Assembly::Load: %p", assemblyLoad->methodPointer);
        } else {
            LOGI("miss Assembly::Load");
            return;
        }
        if (assemblyGetTypes && assemblyGetTypes->methodPointer) {
            LOGI("Assembly::GetTypes: %p", assemblyGetTypes->methodPointer);
        } else {
            LOGI("miss Assembly::GetTypes");
            return;
        }
        typedef void *(*Assembly_Load_ftn)(void *, Il2CppString *, void *);
        typedef Il2CppArray *(*Assembly_GetTypes_ftn)(void *, void *);
        for (int i = 0; i < size; ++i) {
            auto image = il2cpp_assembly_get_image(assemblies[i]);
            std::stringstream imageStr;
            auto image_name = il2cpp_image_get_name(image);
            imageStr << "\n// Dll : " << image_name;
            //LOGD("image name : %s", image->name);
            auto imageName = std::string(image_name);
            auto pos = imageName.rfind('.');
            auto imageNameNoExt = imageName.substr(0, pos);
            auto assemblyFileName = il2cpp_string_new(imageNameNoExt.data());
            auto reflectionAssembly = ((Assembly_Load_ftn) assemblyLoad->methodPointer)(nullptr,
                                                                                        assemblyFileName,
                                                                                        nullptr);
            auto reflectionTypes = ((Assembly_GetTypes_ftn) assemblyGetTypes->methodPointer)(
                    reflectionAssembly, nullptr);
            auto items = reflectionTypes->vector;
            for (int j = 0; j < reflectionTypes->max_length; ++j) {
                auto klass = il2cpp_class_from_system_type((Il2CppReflectionType *) items[j]);
                auto type = il2cpp_class_get_type(klass);
                //LOGD("type name : %s", il2cpp_type_get_name(type));
                auto outPut = imageStr.str() + dump_type(type, &collector);
                outPuts.push_back(outPut);
            }
        }
    }

    auto filesDir = std::string(outDir).append("/files");
    auto dumpDir = filesDir + "/Il2CppDumper";
    ensure_dir(filesDir);
    ensure_dir(dumpDir);

    LOGI("write dump files");
    std::stringstream dumpCs;
    dumpCs << imageOutput.str();
    auto count = outPuts.size();
    for (int i = 0; i < count; ++i) {
        dumpCs << outPuts[i];
    }

    // 保留旧路径，兼容原 README 和已有拉取脚本；新目录放接近桌面版 Il2CppDumper 的输出结构。
    write_text_file(filesDir + "/dump.cs", dumpCs.str());
    write_text_file(dumpDir + "/dump.cs", dumpCs.str());
    write_script_json(dumpDir + "/script.json", collector);
    write_text_file(dumpDir + "/stringliteral.json", "[]\n");
    write_text_file(dumpDir + "/il2cpp.h",
                    "/*\n"
                    " * Runtime Zygisk dump header.\n"
                    " * This is a minimal parser shim for function signatures only.\n"
                    " * Use desktop Il2CppDumper with libil2cpp.so and global-metadata.dat\n"
                    " * when you need full class/field layouts.\n"
                    " */\n"
                    "typedef int bool;\n"
                    "typedef void(*Il2CppMethodPointer)();\n"
                    "struct MethodInfo { Il2CppMethodPointer methodPointer; };\n"
                    "struct Il2CppClass;\n"
                    "struct Il2CppObject { Il2CppClass *klass; void *monitor; };\n");
    write_text_file(dumpDir + "/ida_py3.py",
                    "# -*- coding: utf-8 -*-\n"
                    "import json\n"
                    "import os\n\n"
                    "imageBase = idaapi.get_imagebase()\n\n"
                    "def get_addr(addr):\n"
                    "    return imageBase + addr\n\n"
                    "def set_name(addr, name):\n"
                    "    ret = idc.set_name(addr, name, SN_NOWARN | SN_NOCHECK)\n"
                    "    if ret == 0:\n"
                    "        idc.set_name(addr, name + '_' + str(addr), SN_NOWARN | SN_NOCHECK)\n\n"
                    "def make_function(start, end):\n"
                    "    next_func = idc.get_next_func(start)\n"
                    "    if next_func < end:\n"
                    "        end = next_func\n"
                    "    if idc.get_func_attr(start, FUNCATTR_START) == start:\n"
                    "        ida_funcs.del_func(start)\n"
                    "    ida_funcs.add_func(start, end)\n\n"
                    "path = idaapi.ask_file(False, '*.json', 'script.json from Zygisk-Il2CppDumper')\n"
                    "header_path = os.path.join(os.path.dirname(path), 'il2cpp.h')\n"
                    "has_header = os.path.exists(header_path)\n"
                    "if has_header:\n"
                    "    parse_decls(open(header_path, 'r').read(), 0)\n"
                    "data = json.loads(open(path, 'rb').read().decode('utf-8'))\n\n"
                    "addresses = data.get('Addresses', [])\n"
                    "for index in range(len(addresses) - 1):\n"
                    "    make_function(get_addr(addresses[index]), get_addr(addresses[index + 1]))\n\n"
                    "for scriptMethod in data.get('ScriptMethod', []):\n"
                    "    addr = get_addr(scriptMethod['Address'])\n"
                    "    set_name(addr, scriptMethod['Name'])\n"
                    "    signature = scriptMethod.get('Signature')\n"
                    "    if has_header and signature:\n"
                    "        try:\n"
                    "            apply_type(addr, parse_decl(signature, 0), 1)\n"
                    "        except Exception as e:\n"
                    "            print('apply_type failed:', hex(addr), signature, e)\n\n"
                    "print('Script finished!')\n");

    LOGI("dump done! methods: %zu, output: %s", collector.scriptMethods.size(), dumpDir.c_str());
}
