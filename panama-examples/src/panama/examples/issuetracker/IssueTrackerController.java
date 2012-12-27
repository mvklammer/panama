/*
 *  Copyright 2004-2010 Robert Brandner (robert.brandner@gmail.com)
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
package panama.examples.issuetracker;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

import panama.annotations.Action;
import panama.annotations.Controller;
import panama.collections.QueryListModel;
import panama.collections.QueryTable;
import panama.collections.Table;
import panama.core.BaseController;
import panama.core.PlainTextTarget;
import panama.core.Target;
import panama.examples.issuetracker.entities.Tag;
import panama.examples.issuetracker.entities.Issue;
import panama.exceptions.NoSuchFieldException;
import panama.filter.Filter;
import panama.form.Form;
import panama.form.FormData;
import panama.form.PersistentBeanField;
import panama.form.ValidatorFactory;
import panama.persistence.PersistentBean;

import com.avaje.ebean.Ebean;
import com.avaje.ebean.Query;

/**
 * @author ridcully
 */
@Controller(alias="issues", defaultAction="list")
public class IssueTrackerController extends BaseController {

	public final static String FORMDATA_KEY = "formdata";

	private Table table;

	private final static Form form;
	static {
		form = new Form();
		form.addFields(Issue.class, Form.EXCLUDE_PROPERTIES, "createdAt");
		form.getField("title").addValidator(ValidatorFactory.getNotEmptyValidator());
		form.addField(new PersistentBeanField("tags", Tag.class));
	}

	public IssueTrackerController() {
		table = registerTable(new QueryTable("issuetable", new QueryListModel(Ebean.createQuery(Issue.class))));
	}

	@Action
	public Target list() {
		return render("issuelist.vm");
	}

	/**
	 * This action shows, how you can use Panama's filter framework to create
	 * Ebean expressions ready to use with Ebean queries.
	 * @return a nice ;-) text
	 */
	@Action
	public Target filter() {
		Filter f = Filter.and(
						Filter.anyEq("bla", "title", "description"),
						Filter.allEq("bla", "title", "description"));
		Query q = Ebean.createQuery(Issue.class);
		q.where(f.asExpression(q, null)).findList();
		return new PlainTextTarget("nice ;-)");
	}

	@Action
	public Target edit() {
		String id = context.getParameter("id");
		Issue e = (Issue)PersistentBean.findOrCreate(Issue.class, id);
		FormData fd = new FormData(form);
		fd.setInput(e);
		fd.setInput("tags", e.getTags().toArray(new Tag[0]));
		return showForm(fd);
	}

	private Target showForm(FormData fd) {
		context.put(FORMDATA_KEY, fd);
		List<Tag> tags = Ebean.createQuery(Tag.class).findList();
		context.put("alltags", tags);
		return render("issueform.vm");
	}

	@Action
	public Target save() {
		if (context.getParameter("ok") != null) {
			FormData fd = new FormData(form);
			fd.setInput(context.getParameterMap());
			String id = fd.getString("id");
			Issue e = (Issue)PersistentBean.findOrCreate(Issue.class, id);
			fd.applyTo(e, Form.EXCLUDE_PROPERTIES, "tags");
			if (fd.hasErrors()) {
				return showForm(fd);
			}
			try {
				Set tags = fd.getValuesAsSet("tags");
				e.setTags(tags);
			} catch (NoSuchFieldException e1) {
				e1.printStackTrace();
			}
			Ebean.save(e);
		}
		return redirectToAction("list");
	}

	@Action
	public Target delete() {
		String id = context.getParameter("id");
		if (id != null) {
			int is = Ebean.delete(Issue.class, id);
		}
		return redirectToAction("list");
	}
}