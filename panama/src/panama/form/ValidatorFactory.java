/*
 *  Copyright 2004-2012 Robert Brandner (robert.brandner@gmail.com)
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package panama.form;

import panama.core.Context;
import panama.exceptions.ValidatorException;

/**
 * <p>A factory for frequently used validators.
 * Keeps a single instance of each validator
 * Regular expressions are taken from the <a href="https://www.owasp.org/index.php/OWASP_Validation_Regex_Repository"> OWASP Validation Regex Repository</a>
 * </p>
 * @author Robert and Valentin
 */
public class ValidatorFactory {

	private static Validator notEmptyValidator = new Validator() {
		public synchronized void validate(Object value) throws ValidatorException {
			if (value == null || value.toString().trim().length() == 0) {
				String msg = Context.getInstance().getLocalizedString(Validator.NOTEMPTY_VALIDATION_FAILED);
				throw new ValidatorException(msg);
			}
		}
	};

	private static Validator emailValidator = new Validator() {

		private final static String EMAIL_PATTERN = "^[a-zA-Z0-9+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$";

		public synchronized void validate(Object value) throws ValidatorException {
			if (value != null && !value.toString().toLowerCase().matches(EMAIL_PATTERN)) {
				String msg = Context.getInstance().getLocalizedString(Validator.EMAIL_VALIDATION_FAILED);
				throw new ValidatorException(msg);
			}
		}
	};

	private static Validator urlValidator = new Validator() {

		private final static String URL_PATTERN = "^((((https?|ftps?|gopher|telnet|nntp)://)|(mailto:|news:))(%[0-9A-Fa-f]{2}|[-()_.!~*';/?:@&=+$,A-Za-z0-9])+)([).!';/?:,][[:blank:]])?$";

		public synchronized void validate(Object value) throws ValidatorException {
			if (value != null && !value.toString().toLowerCase().matches(URL_PATTERN)) {
				String msg = Context.getInstance().getLocalizedString(Validator.URL_VALIDATION_FAILED);
				throw new ValidatorException(msg);
			}
		}
	};

	private static Validator ipValidator = new Validator() {

		private final static String IP_PATTERN = "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";

		public synchronized void validate(Object value) throws ValidatorException {
			if (value != null && !value.toString().toLowerCase().matches(IP_PATTERN)) {
				String msg = Context.getInstance().getLocalizedString(Validator.IP_VALIDATION_FAILED);
				throw new ValidatorException(msg);
			}
		}
	};

	/**
	 * <p>Lower and upper case letters and all digits
	 * Always use this if there is text input from the user.
	 * If you need to validate rich content user input use sanitizers like <a href="https://github.com/owasp/java-html-sanitizer">OWASP HTML sanitizer</p>
	 */
	private static Validator safeTextValidator = new Validator() {

		private final static String SAFETEXT_PATTERN = "^[a-zA-Z0-9 .-]+$";

		public synchronized void validate(Object value) throws ValidatorException {
			if (value != null && !value.toString().toLowerCase().matches(SAFETEXT_PATTERN)) {
				String msg = Context.getInstance().getLocalizedString(Validator.SAFETEXT_VALIDATION_FAILED);
				throw new ValidatorException(msg);
			}
		}
	};

	/**
	 * 4 to 8 character password requiring numbers and both lowercase and uppercase letters
	 */
	private static Validator simplePasswordValidator = new Validator() {

		private final static String SIMPLEPASSWORD_PATTERN = "^[a-zA-Z0-9 .-]+$";

		public synchronized void validate(Object value) throws ValidatorException {
			if (value != null && !value.toString().toLowerCase().matches(SIMPLEPASSWORD_PATTERN)) {
				String msg = Context.getInstance().getLocalizedString(Validator.SIMPLEPASSWORD_VALIDATION_FAILED);
				throw new ValidatorException(msg);
			}
		}
	};

	/**
	 * <p>4 to 32 character password requiring at least 3 out 4 (uppercase and
	 * lowercase letters, numbers and special characters) and no more than 2 equal characters in a row</p>
	 */
	private static Validator complexPasswordValidator = new Validator() {

		private final static String COMPLEXPASSWORD_PATTERN = "^[a-zA-Z0-9 .-]+$";

		public synchronized void validate(Object value) throws ValidatorException {
			if (value != null && !value.toString().toLowerCase().matches(COMPLEXPASSWORD_PATTERN)) {
				String msg = Context.getInstance().getLocalizedString(Validator.COMPLEXPASSWORD_VALIDATION_FAILED);
				throw new ValidatorException(msg);
			}
		}
	};

	/**
	 * Matches Names like "Jon M. Doe",  "Tim L. O'Doul"
	 */
	private static Validator safeNameValidator = new Validator() {

		private final static String SAFENAME_PATTERN = "^([a-zA-Z.\\s']{1,50})$";

		public synchronized void validate(Object value) throws ValidatorException {
			if (value != null && !value.toString().toLowerCase().matches(SAFENAME_PATTERN)) {
				String msg = Context.getInstance().getLocalizedString(Validator.SAFENAME_VALIDATION_FAILED);
				throw new ValidatorException(msg);
			}
		}
	};

	public static Validator getNotEmptyValidator() {
		return notEmptyValidator;
	}

	public static Validator getEmailValidator() {
		return emailValidator;
	}

	public static Validator getUrlValidator() {
		return urlValidator;
	}

	public static Validator getIpValidator() {
		return ipValidator;
	}

	public static Validator getSafeTextValidator() {
		return safeTextValidator;
	}

	public static Validator getSimplePasswordValidator() {
		return simplePasswordValidator;
	}

	public static Validator getComplexPasswordValidator() {
		return complexPasswordValidator;
	}

	public static Validator getSafeNameValidator() {
		return safeNameValidator;
	}
}
