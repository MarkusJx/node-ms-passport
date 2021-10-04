#include <Windows.h>

#include "CLITools.hpp"

using namespace System::Reflection;

// The location of the C# dll
char cSharpDllLocation[MAX_PATH + 1];

void CLITools::setDllLocation(const std::string &location) {
	memset(cSharpDllLocation, '\0', sizeof(cSharpDllLocation));
	strcpy_s(cSharpDllLocation, location.c_str());
}

String^ CLITools::getDllLocation() {
	return std_string_to_string(cSharpDllLocation);
}

void CLITools::callVoidCSFunction(String^ cls, String^ name, array<Object^>^ data) {
	String^ dll = std_string_to_string(cSharpDllLocation) + "CSNodeMsPassport.dll";
	Assembly^ assembly = Assembly::LoadFrom(dll);
	MethodInfo^ m = assembly->GetType(cls)->GetMethod(name);

	m->Invoke(nullptr, data);
}

password_vault::login_data CLITools::convertLoginData(Object^ data) {
    String ^ dll = getDllLocation() + "CSNodeMsPassport.dll";
    Assembly ^ assembly = Assembly::LoadFrom(dll);
    Type^ LoginData = data->GetType();

	String^ username_cs = static_cast<String^>(LoginData->GetField("Username")->GetValue(data));
	String^ password_cs = static_cast<String^>(LoginData->GetField("Password")->GetValue(data));

	std::wstring username = string_to_std_wstring(username_cs);
    secure_wstring password = string_to_secure_wstring(password_cs);

	return password_vault::login_data(username, password);
}

std::string CLITools::wstring_to_string(const std::wstring& in) {
	std::string out(in.size() + 1, '\0');
	size_t outSize;

	errno_t err = wcstombs_s(&outSize, (char*)out.data(), out.size(), in.c_str(), in.size());
	if (err) {
		perror("Error creating string");
		return std::string();
	}

	out.resize(outSize);
	return out;
}

std::string CLITools::string_to_std_string(String^ s) {
	return wstring_to_string(string_to_std_wstring(s));
}

std::wstring CLITools::string_to_std_wstring(String^ s) {
    array<wchar_t> ^ arr = s->ToCharArray();
    int size = arr->Length;
    std::wstring out(size, '\0');
    for (int i = 0; i < size; i++) {
        out[i] = arr[i];
    }

	return out;
}

secure_wstring CLITools::string_to_secure_wstring(String^ s) {
    array<wchar_t> ^ arr = s->ToCharArray();
    int size = arr->Length;
    secure_wstring out(size, '\0');
    for (int i = 0; i < size; i++) {
        out[i] = arr[i];
    }

	return out;
}

String^ CLITools::std_string_to_string(const std::string& in) {
	std::wstring w_str = std::wstring(in.begin(), in.end());
	return gcnew String(w_str.c_str());
}

String^ CLITools::std_wstring_to_string(const std::wstring &in) {
    return gcnew String(in.c_str());
}

String^ CLITools::secure_wstring_to_string(const secure_wstring &in) {
    return gcnew String(in.c_str());
}

secure_vector<byte> CLITools::byteArrayToVector(array<byte>^ data) {
	secure_vector<byte> out(data->Length, 0);
	for (int i = 0; i < data->Length; i++) {
		out[i] = data[i];
	}

	return out;
}

array<unsigned char>^ CLITools::byteVectorToArray(const secure_vector<byte>& in) {
	array<byte>^ out = gcnew array<byte>(in.size());
	for (int i = 0; i < in.size(); i++) {
		out[i] = in[i];
	}

	return out;
}

bool CLITools::convertBoolean(Boolean val) {
	return val ? true : false;
}

void CLITools::clearArray(array<byte>^ arr) {
	for (int i = 0; i < arr->Length; i++) {
		arr[i] = 0;
	}
}
