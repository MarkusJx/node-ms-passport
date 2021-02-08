using System;

namespace CSNodeMsPassport {
    /// <summary>
    /// An exception to be thrown when the access was denied
    /// </summary>
    class AccessDeniedException : Exception {
        /// <summary>
        /// Create an AccessDeniedException instance
        /// </summary>
        public AccessDeniedException() : base("The access was denied") {
            base.HResult = 8;
        }
    }

    /// <summary>
    /// An exception to be thrown when a key was already deleted
    /// </summary>
    class KeyAlreadyDeletedException : Exception {
        /// <summary>
        /// Create a KeyAlredyDeletedException instance
        /// </summary>
        public KeyAlreadyDeletedException() : base("The key is already deleted") {
            base.HResult = 7;
        }
    }

    /// <summary>
    /// An exception to be thrown when a sign operation failed
    /// </summary>
    class SignOperationFailedException : Exception {
        /// <summary>
        /// Create a SignOperationFailedException instance
        /// </summary>
        public SignOperationFailedException() : base("The sign operation failed") {
            base.HResult = 6;
        }
    }

    /// <summary>
    /// An exception to be thrown when an account was not found
    /// </summary>
    class AccountNotFoundException : Exception {
        /// <summary>
        /// Create an AccountNotFoundException instance
        /// </summary>
        public AccountNotFoundException() : base("The specified account was not found") {
            base.HResult = 5;
        }
    }

    /// <summary>
    /// An exception to be thrown when the user prefers a password
    /// </summary>
    class UserPrefersPasswordException : Exception {
        /// <summary>
        /// Create an UserPrefersPasswordException instance
        /// </summary>
        public UserPrefersPasswordException() : base("The user prefers a password") {
            base.HResult = 4;
        }
    }

    /// <summary>
    /// An exception to be thrown when the user cancelled the operation
    /// </summary>
    class UserCancelledException : Exception {
        /// <summary>
        /// Create an UserCancelledException instance
        /// </summary>
        public UserCancelledException() : base("The user cancelled the passport enrollment process") {
            base.HResult = 3;
        }
    }

    /// <summary>
    /// An exception to be thrown when the user needs to create a pin
    /// </summary>
    class MissingPinException : Exception {
        /// <summary>
        /// Create a MissingPinException instance
        /// </summary>
        public MissingPinException() : base("The user needs to create a pin") {
            base.HResult = 2;
        }
    }

    /// <summary>
    /// An exception to be thrown when an unknown error occurred
    /// </summary>
    class UnknownException : Exception {
        /// <summary>
        /// Create an UnknownException instance
        /// </summary>
        public UnknownException() : base("An unknown error occurred") {
            base.HResult = 1;
        }
    }
}