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
package panama.filter;

import java.io.Serializable;
import java.util.Collection;
import java.util.Map;

import com.avaje.ebean.Ebean;
import com.avaje.ebean.Expression;
import com.avaje.ebean.Query;

/**
 * Base class and Factory for filters of all kinds.
 *
 * @author Ridcully
 *
 */
public class Filter implements Serializable {

	protected static final long serialVersionUID = 1L;

	/**
	 * This method applies the Filter onto the specified object. The method in this base class
	 * simply returns true, classes extending this class will return more useful values.
	 *
	 * @param object
	 * @return wether the specified object matches the filter.
	 */
	public boolean match(Object object) {
		return match(object, null);
	}

	/**
	 * This method applies the Filter onto the specified object. The method in this base class
	 * simply returns true, classes extending this class will return more useful values.
	 *
	 * @param object
	 * @param filterExtensions a Map<propertyName, FilterExtension> for additional stuff
	 * @return wether the specified object matches the filter.
	 */
	public boolean match(Object object, Map<String, FilterExtension> filterExtensions) {
		return true;
	}

	/**
	 * Creates representation of the Filter for use with Ebean Expression model.
	 * The method in this base class simply returns an 'always true' expression, classes extending this class
	 * will return more useful values.
	 * @param filterExtensions A Map<propertyName, FilterExtension> with optional stuff for special filter treatments
	 * @return an Expression representing the Filter.
	 */
	public Expression asExpression(Query<?> query, Map<String, FilterExtension> filterExtensions) {
		return Ebean.getExpressionFactory().raw("1=1");
	}


	/**
	 * Gets a string representation of the filter.
	 * @return A string representation of the filter.
	 */
	public String toString() {
		return super.toString();
	}

	// ---- Factory methods --------------------------------------------------

	/**
	 * Creates a standard search filter that is case insensitive and matches ^.*pattern.*$.
	 */
	public static Filter stdSearchFilter(String pattern, String... propertyNames) {
		return new SearchPropertyComparator(pattern, PropertyComparator.ANY_PROPERTIES, propertyNames);
	}

	public static Filter anyEq(String pattern, String... propertyNames) {
		return new PropertyComparator(pattern, PropertyComparator.ANY_PROPERTIES, propertyNames);
	}

	public static Filter noneEq(String pattern, String... propertyNames) {
		return new PropertyComparator(pattern, PropertyComparator.NO_PROPERTIES, propertyNames);
	}

	public static Filter allEq(String pattern, String... propertyNames) {
		return new PropertyComparator(pattern, PropertyComparator.ALL_PROPERTIES, propertyNames);
	}

	public static Filter anyMatches(String pattern, String... propertyNames) {
		return new RegExpPropertyComparator(pattern, PropertyComparator.ANY_PROPERTIES, propertyNames);
	}

	public static Filter noneMatches(String pattern, String... propertyNames) {
		return new RegExpPropertyComparator(pattern, PropertyComparator.NO_PROPERTIES, propertyNames);
	}

	public static Filter allMatch(String pattern, String... propertyNames) {
		return new RegExpPropertyComparator(pattern, PropertyComparator.ALL_PROPERTIES, propertyNames);
	}

	public static Filter and(Filter lhs, Filter rhs) {
		return new LogicalExpression(LogicalExpression.AND, lhs, rhs);
	}

	public static Filter or(Filter lhs, Filter rhs) {
		return new LogicalExpression(LogicalExpression.OR, lhs, rhs);
	}

	public static Filter not(Filter filter) {
		return new LogicalExpression(LogicalExpression.NOT, filter);
	}

	public static Filter all(Filter... filters) {
		return new LogicalExpression(LogicalExpression.AND, filters);
	}

	public static Filter all(Collection<Filter> filters) {
		return new LogicalExpression(LogicalExpression.AND, filters.toArray(new Filter[0]));
	}

	public static Filter any(Filter... filters) {
		return new LogicalExpression(LogicalExpression.OR, filters);
	}

	public static Filter any(Collection<Filter> filters) {
		return new LogicalExpression(LogicalExpression.OR, filters.toArray(new Filter[0]));
	}

	public static Filter withExpression(Expression expression) {
		return new ExpressionFilter(expression);
	}
}
