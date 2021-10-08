#ifndef PASSPORT_CLITOOLS_HPP
#define PASSPORT_CLITOOLS_HPP

#include "NodeMsPassport.hpp"

using namespace System;
using namespace nodeMsPassport;

namespace CLITools {
	/**
	 * Set the location of the C# dll
	 * 
	 * @param loc the location of the dll
	 */
	void setDllLocation(const std::string& loc);

	/**
	 * Get the location of the C# dll
	 * 
	 * @return the location of the C# dll
	 */
	String^ getDllLocation();

	/**
	 * Convert a std::wstring to a std::string
	 *
	 * @param in the string to convert
	 * @return the converted string
	 */
	std::string wstring_to_string(const std::wstring& in);

	/**
	 * Convert a managed System::String to a std::string
	 *
	 * @param s the string to convert
	 * @return the converted C++ std::string
	 */
	std::string string_to_std_string(String^ s);

	/**
	 * Convert a unmanaged character array to a managed string.
	 * Does not delete the character array.
	 * Source: https://stackoverflow.com/a/39249779
	 *
	 * @param char_array the char array to convert
	 * @return the System::String
	 */
	String^ std_string_to_string(const std::string& in);

	/**
	* Convert a managed byte array to a character array.
	*
	* @param data the array to convert
	* @return the converted char array
	*/
	secure_vector<byte> byteArrayToVector(array<byte>^ data);

	/**
	* Convert a char array to a managed byte array.
	* Does not delete the input array
	*
	* @param data the array to convert
	* @param len the length of the input array
	* @return the managed byte array
	*/
	array<unsigned char>^ byteVectorToArray(const secure_vector<byte>& in);

	/**
	 * Convert a managed boolean to an unmanaged boolean
	 *
	 * @param val the value to convert
	 * @return the converted boolean
	 */
	bool convertBoolean(Boolean val);

	/**
	 * Call a passport function
	 *
	 * @tparam T the output type
	 * @param name the name of the function to call
	 * @param data the data to pass on to the function
	 * @return the function return value
	 */
	template<class T>
	inline T callPassportFunction(String^ name, array<Object^ >^ data) {
		String^ dll = getDllLocation() + "CSNodeMsPassport.dll";
		Assembly^ assembly = Assembly::LoadFrom(dll);
		MethodInfo^ m = assembly->GetType("CSNodeMsPassport.Passport")->GetMethod(name);

		return static_cast<T>(m->Invoke(nullptr, data));
	}

	/**
	 * Call a passport void function
	 *
	 * @param name the name of the function to call
	 * @param data the data to pass on to the function
	 */
	void callVoidPassportFunction(String^ name, array<Object^>^ data);

	/**
	 * Convert any C++ type to a managed object
	 * 
	 * @tparam T the type of the value to convert
	 * @param val the value to convert
	 * @return the converted object
	 */
	template<class T>
	inline Object^ anyToObject(const T& val) {
		static_assert(std::is_same_v<T, std::string> || std::is_same_v<T, secure_vector<byte>>);
		if constexpr (std::is_same_v<T, std::string>) {
			return std_string_to_string(val);
		} else if constexpr (std::is_same_v<T, secure_vector<byte>>) {
			return byteVectorToArray(val);
		}
	}

	/**
	 * Convert template arguments to an object array
	 * 
	 * @tparam Args the argument types
	 * @param args the actual arguments
	 * @return the managed object array
	 */
	template<class...Args>
	inline array<Object^>^ convertArgs(Args...args) {
		if constexpr (sizeof...(Args) > 0) {
			array<Object^>^ arr = gcnew array<Object^>(sizeof...(Args));
			int i = 0;
			volatile auto x = { (arr[i++] = anyToObject(args), 0)... };

			return arr;
		} else {
			return nullptr;
		}
	}

	/**
	 * Zero out a managed byte array
	 *
	 * @param arr the array to zero out
	 */
	void clearArray(array<byte>^ arr);

	/**
	 * Call a C# function using reflection
	 * 
	 * @tparam T the return type
	 * @tparam Args the argument types
	 * @param name the name of the function to call
	 * @param args the function arguments. May be empty for no arguments.
	 * @return the function call result
	 */
	template<class T, class...Args>
	inline T callFunc(String^ name, Args...args) {
		static_assert(std::is_same_v<bool, T> || std::is_same_v<secure_vector<byte>, T> || std::is_same_v<void, T> ||
                      std::is_same_v<int, T>);
        if constexpr (std::is_same_v<bool, T>) {
            Boolean ret = callPassportFunction<Boolean>(name, convertArgs(std::forward<Args>(args)...));
            return convertBoolean(ret);
        } else if constexpr (std::is_same_v<int, T>) {
            return callPassportFunction<int>(name, convertArgs(std::forward<Args>(args)...));
		} else if constexpr (std::is_same_v<secure_vector<byte>, T>) {
            array<byte> ^ ret = callPassportFunction<array<byte> ^>(name, convertArgs(std::forward<Args>(args)...));
			secure_vector<byte> out = byteArrayToVector(ret);
			clearArray(ret);

			return out;
		} else if constexpr (std::is_same_v<void, T>) {
            callVoidPassportFunction(name, convertArgs(std::forward<Args>(args)...));
		}
	}
}

#endif //PASSPORT_CLITOOLS_HPP
