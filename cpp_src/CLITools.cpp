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

void CLITools::callVoidPassportFunction(String^ name, array<Object^>^ data) {
	String^ dll = std_string_to_string(cSharpDllLocation) + "CSNodeMsPassport.dll";
	Assembly^ assembly = Assembly::LoadFrom(dll);
	MethodInfo^ m = assembly->GetType("CSNodeMsPassport.Passport")->GetMethod(name);

	m->Invoke(nullptr, data);
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
	array<wchar_t>^ arr = s->ToCharArray();
	int size = arr->Length;
	std::wstring out(size, '\0');
	for (int i = 0; i < size; i++) {
		out[i] = arr[i];
	}

	return wstring_to_string(out);
}

String^ CLITools::std_string_to_string(const std::string& in) {
	std::wstring w_str = std::wstring(in.begin(), in.end());
	return gcnew String(w_str.c_str());
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
