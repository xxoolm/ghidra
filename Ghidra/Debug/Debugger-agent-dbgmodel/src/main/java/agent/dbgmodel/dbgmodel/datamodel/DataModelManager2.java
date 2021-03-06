/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package agent.dbgmodel.dbgmodel.datamodel;

import com.sun.jna.WString;
import com.sun.jna.platform.win32.Variant.VARIANT.ByReference;

import agent.dbgmodel.dbgmodel.debughost.DebugHostContext;
import agent.dbgmodel.dbgmodel.debughost.DebugHostType1;
import agent.dbgmodel.dbgmodel.main.KeyStore;
import agent.dbgmodel.dbgmodel.main.ModelObject;

/**
 * A wrapper for {@code IDataModelManager2} and its newer variants.
 */
public interface DataModelManager2 extends DataModelManager1 {

	ModelObject acquireSubNamespace(WString modelName, WString subNamespaceModelName,
			WString accessName, KeyStore metadata);

	ModelObject createTypedIntrinsicObjectEx(DebugHostContext context, ByReference intrinsicData,
			DebugHostType1 type);
}
