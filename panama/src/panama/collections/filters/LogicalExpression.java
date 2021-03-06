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
package panama.collections.filters;

import com.avaje.ebean.Ebean;
import com.avaje.ebean.Expression;
import com.avaje.ebean.Junction;
import com.avaje.ebean.Query;

/**
 * Provides the logical operators AND, OR and NOT
 * @author Ridcully
 *
 */
public class LogicalExpression extends Filter {

	private static final long serialVersionUID = 1L;

	// Operators as numbers for more speed
	public final static int AND = 1;
	public final static int OR = 2;
	public final static int NOT = 3;

	protected Filter[] filters;
	protected int op = 0;

	public LogicalExpression(int op, Filter... filters) {
		this.filters = filters;
		this.op = op;
	}

	@Override
	public boolean match(Object object) {
		switch (op) {
			case AND :	for (Filter f : filters) {
							if (!f.match(object)) { return false; }
						}
						return true;
			case OR : 	for (Filter f : filters) {
							if (f.match(object)) { return true; }
						}
						return false;
			case NOT : 	return !filters[0].match(object);
		}
		return false;
	}

	public String toString() {
		StringBuffer res = new StringBuffer();
		switch (op) {
			case AND :
				for (int i=0; i<filters.length; i++) {
					if (i > 0) { res.append(" AND "); }
					res.append("(").append(filters[i]).append(")");
				}
				break;
			case OR :
				for (int i=0; i<filters.length; i++) {
					if (i > 0) { res.append(" OR "); }
					res.append("(").append(filters[i]).append(")");
				}
				break;
			case NOT : res.append("NOT (").append(filters[0]).append(")"); break;
		}
		return res.toString();
	}

	@Override
	public Expression asExpression(Query<?> query) {
		switch (op) {
			case AND :
				Junction<?> all = Ebean.getExpressionFactory().conjunction(query);
				for (Filter f : filters) {
					all.add(f.asExpression(query));
				}
				return all;
			case OR :
				Junction<?> any = Ebean.getExpressionFactory().disjunction(null);
				for (Filter f : filters) {
					any.add(f.asExpression(query));
				}
				return any;
			case NOT : return Ebean.getExpressionFactory().not(filters[0].asExpression(query));
		}
		return null;
	}
}
