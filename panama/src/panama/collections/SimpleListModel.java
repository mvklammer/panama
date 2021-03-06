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
package panama.collections;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * 
 * @author Ridcully
 *
 */
public class SimpleListModel implements ListModel, Serializable {

	private static final long serialVersionUID = 1L;
	
	private List list;
	protected Table table = null;
	
	public SimpleListModel() {
	}
	
	public SimpleListModel(List<? extends Object> list) {
		setList(list);
	}
	
	/** {@inheritDoc} */
	@Override
	public List<? extends Object> getList() {
		return new ArrayList(list);
	}

	/** {@inheritDoc} */
	@Override
	public void setTable(Table table) {
		this.table = table;
	}	

	/**
	 * Set the data, the ListModel shall hold.
	 * @param list
	 */
	public void setList(List<? extends Object> list) {
		this.list = list;
	}
}
