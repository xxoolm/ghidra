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
package ghidra.trace.model.target.iface;

import java.lang.annotation.*;
import java.lang.invoke.MethodType;
import java.lang.reflect.Parameter;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.trace.model.target.info.TraceObjectInfo;

/**
 * An object which can be invoked as a method
 * 
 * <p>
 * TODO: Should parameters and return type be something incorporated into Schemas?
 * 
 * <p>
 * NOTE: We might keep this around a bit longer, since some connectors may like to reflect an object
 * model that presents methods in the tree. The connector will need to provide the means of
 * invocation, and that may become better integrated into the UI, but at least for now, being able
 * to show and hide them is important, so we at least need a named interface for them.
 */
@TraceObjectInfo(
	schemaName = "Method",
	shortName = "method",
	attributes = {
	// LATER?: Parameter map, return type
	},
	fixedKeys = {})
public interface TraceMethod extends TraceObjectInterface {

	interface Value<T> {
		boolean specified();

		T value();
	}

	@interface BoolValue {
		boolean specified() default true;

		boolean value();

		record Val(BoolValue v) implements Value<Boolean> {
			@Override
			public boolean specified() {
				return v.specified();
			}

			@Override
			public Boolean value() {
				return v.value();
			}
		}
	}

	@interface IntValue {
		boolean specified() default true;

		int value();

		record Val(IntValue v) implements Value<Integer> {
			@Override
			public boolean specified() {
				return v.specified();
			}

			@Override
			public Integer value() {
				return v.value();
			}
		}
	}

	@interface LongValue {
		boolean specified() default true;

		long value();

		record Val(LongValue v) implements Value<Long> {
			@Override
			public boolean specified() {
				return v.specified();
			}

			@Override
			public Long value() {
				return v.value();
			}
		}
	}

	@interface FloatValue {
		boolean specified() default true;

		float value();

		record Val(FloatValue v) implements Value<Float> {
			@Override
			public boolean specified() {
				return v.specified();
			}

			@Override
			public Float value() {
				return v.value();
			}
		}
	}

	@interface DoubleValue {
		boolean specified() default true;

		double value();

		record Val(DoubleValue v) implements Value<Double> {
			@Override
			public boolean specified() {
				return v.specified();
			}

			@Override
			public Double value() {
				return v.value();
			}
		}
	}

	@interface BytesValue {
		boolean specified() default true;

		byte[] value();

		record Val(BytesValue v) implements Value<byte[]> {
			@Override
			public boolean specified() {
				return v.specified();
			}

			@Override
			public byte[] value() {
				return v.value();
			}
		}
	}

	@interface StringValue {
		boolean specified() default true;

		String value();

		record Val(StringValue v) implements Value<String> {
			@Override
			public boolean specified() {
				return v.specified();
			}

			@Override
			public String value() {
				return v.value();
			}
		}
	}

	@interface StringsValue {
		boolean specified() default true;

		String[] value();

		record Val(StringsValue v) implements Value<List<String>> {
			@Override
			public boolean specified() {
				return v.specified();
			}

			@Override
			public List<String> value() {
				return List.of(v.value());
			}
		}
	}

	// TODO: Address, Range, BreakKind[Set], etc?

	@Target(ElementType.PARAMETER)
	@Retention(RetentionPolicy.RUNTIME)
	@interface Param {
		List<Function<Param, Value<?>>> DEFAULTS = List.of(
			p -> new BoolValue.Val(p.defaultBool()),
			p -> new IntValue.Val(p.defaultInt()),
			p -> new LongValue.Val(p.defaultLong()),
			p -> new FloatValue.Val(p.defaultFloat()),
			p -> new DoubleValue.Val(p.defaultDouble()),
			p -> new BytesValue.Val(p.defaultBytes()),
			p -> new StringValue.Val(p.defaultString()));

		String name() default "";

		String display() default "";

		String description() default "";

		String schema() default "ANY";

		// TODO: Something that hints at changes in activation?

		boolean required() default true;

		BoolValue defaultBool() default @BoolValue(specified = false, value = false);

		IntValue defaultInt() default @IntValue(specified = false, value = 0);

		LongValue defaultLong() default @LongValue(specified = false, value = 0);

		FloatValue defaultFloat() default @FloatValue(specified = false, value = 0);

		DoubleValue defaultDouble() default @DoubleValue(specified = false, value = 0);

		BytesValue defaultBytes() default @BytesValue(specified = false, value = {});

		StringValue defaultString() default @StringValue(specified = false, value = "");

		StringsValue choicesString() default @StringsValue(specified = false, value = {});
	}

	/**
	 * A description of a method parameter
	 * 
	 * <P>
	 * TODO: Should this be incorporated into schemas?
	 * 
	 * @param <T> the type of the parameter
	 */
	class ParameterDescription<T> {
		/**
		 * Create a parameter
		 * 
		 * @param <T> the type of the parameter
		 * @param type the class representing the type of the parameter
		 * @param name the name of the parameter
		 * @param required true if this parameter must be provided
		 * @param defaultValue the default value of this parameter
		 * @param display the human-readable name of this parameter
		 * @param description the human-readable description of this parameter
		 * @param schema the parameter's schema
		 * @return the new parameter description
		 */
		public static <T> ParameterDescription<T> create(Class<T> type, String name,
				boolean required, T defaultValue, String display, String description,
				String schema) {
			return new ParameterDescription<>(type, name, required, defaultValue, display,
				description, schema, List.of());
		}

		/**
		 * Create a parameter
		 * 
		 * @param <T> the type of the parameter
		 * @param type the class representing the type of the parameter
		 * @param name the name of the parameter
		 * @param required true if this parameter must be provided
		 * @param defaultValue the default value of this parameter
		 * @param display the human-readable name of this parameter
		 * @param description the human-readable description of this parameter
		 * @return the new parameter description
		 */
		public static <T> ParameterDescription<T> create(Class<T> type, String name,
				boolean required, T defaultValue, String display, String description) {
			return new ParameterDescription<>(type, name, required, defaultValue, display,
				description, "ANY", List.of());
		}

		/**
		 * Create a parameter having enumerated choices
		 * 
		 * @param <T> the type of the parameter
		 * @param type the class representing the type of the parameter
		 * @param name the name of the parameter
		 * @param choices the non-empty set of choices. The first is the default.
		 * @param display the human-readable name of this parameter
		 * @param description the human-readable description of this parameter
		 * @return the new parameter description
		 */
		public static <T> ParameterDescription<T> choices(Class<T> type, String name,
				Collection<T> choices, String display, String description) {
			T defaultValue = choices.iterator().next();
			return new ParameterDescription<>(type, name, false, defaultValue, display, description,
				"ANY", choices);
		}

		/**
		 * Create a parameter having enumerated choices
		 * 
		 * @param <T> the type of the parameter
		 * @param type the class representing the type of the parameter
		 * @param name the name of the parameter
		 * @param choices the non-empty set of choices
		 * @param defaultValue the default value of this parameter
		 * @param display the human-readable name of this parameter
		 * @param description the human-readable description of this parameter
		 * @return the new parameter description
		 */
		public static <T> ParameterDescription<T> choices(Class<T> type, String name,
				Collection<T> choices, T defaultValue, String display, String description) {
			if (!choices.contains(defaultValue)) {
				throw new IllegalArgumentException("Default must be one of the choices.");
			}
			return new ParameterDescription<>(type, name, false, defaultValue, display, description,
				"ANY", choices);
		}

		protected static boolean isRequired(Class<?> type, Param param) {
			if (!type.isPrimitive()) {
				return param.required();
			}
			if (type == boolean.class) {
				return !param.defaultBool().specified();
			}
			if (type == int.class) {
				return !param.defaultInt().specified();
			}
			if (type == long.class) {
				return !param.defaultLong().specified();
			}
			if (type == float.class) {
				return !param.defaultFloat().specified();
			}
			if (type == double.class) {
				return !param.defaultDouble().specified();
			}
			throw new IllegalArgumentException("Parameter type not allowed: " + type);
		}

		protected static Object getDefault(Param annot) {
			List<Object> defaults = new ArrayList<>();
			for (Function<Param, Value<?>> df : Param.DEFAULTS) {
				Value<?> value = df.apply(annot);
				if (value.specified()) {
					defaults.add(value.value());
				}
			}
			if (defaults.isEmpty()) {
				return null;
			}
			if (defaults.size() > 1) {
				throw new IllegalArgumentException(
					"Can only specify one default value. Got " + defaults);
			}
			return defaults.get(0);
		}

		protected static <T> T getDefault(Class<T> type, Param annot) {
			Object dv = getDefault(annot);
			if (dv == null) {
				return null;
			}
			if (!type.isInstance(dv)) {
				throw new IllegalArgumentException(
					"Type of default does not match that of parameter. Expected type " + type +
						". Got (" + dv.getClass() + ")" + dv);
			}
			return type.cast(dv);
		}

		protected static <T> ParameterDescription<T> annotated(Class<T> type, Param annot,
				String name) {
			boolean required = isRequired(type, annot);
			T defaultValue = getDefault(type, annot);
			return ParameterDescription.create(type, name,
				required, defaultValue, annot.display(), annot.description(), annot.schema());
		}

		public static ParameterDescription<?> annotated(Parameter parameter) {
			Param annot = parameter.getAnnotation(Param.class);
			if (annot == null) {
				throw new IllegalArgumentException(
					"Missing @" + Param.class.getSimpleName() + " on " + parameter);
			}
			String name = annot.name().equals("") ? parameter.getName() : annot.name();
			if (annot.choicesString().specified()) {
				if (parameter.getType() != String.class) {
					throw new IllegalArgumentException(
						"Can only specify choices for String parameter");
				}
				return ParameterDescription.choices(String.class, name,
					List.of(annot.choicesString().value()), annot.display(), annot.description(),
					annot.schema());
			}
			return annotated(MethodType.methodType(parameter.getType()).wrap().returnType(), annot,
				name);
		}

		public final Class<T> type;
		public final String name;
		public final T defaultValue;
		public final boolean required;
		public final String display;
		public final String description;
		public final String schema;
		public final Set<T> choices;

		private ParameterDescription(Class<T> type, String name, boolean required, T defaultValue,
				String display, String description, String schema, Collection<T> choices) {
			this.type = type;
			this.name = name;
			this.defaultValue = defaultValue;
			this.required = required;
			this.display = display;
			this.description = description;
			this.schema = schema;
			this.choices = Set.copyOf(choices);
		}

		@Override
		public int hashCode() {
			return Objects.hash(type, name, defaultValue, required, display, description, choices);
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof ParameterDescription<?>)) {
				return false;
			}
			ParameterDescription<?> that = (ParameterDescription<?>) obj;
			if (this.type != that.type) {
				return false;
			}
			if (!Objects.equals(this.name, that.name)) {
				return false;
			}
			if (!Objects.equals(this.defaultValue, that.defaultValue)) {
				return false;
			}
			if (this.required != that.required) {
				return false;
			}
			if (!Objects.equals(this.display, that.display)) {
				return false;
			}
			if (!Objects.equals(this.description, that.description)) {
				return false;
			}
			if (!Objects.equals(this.choices, that.choices)) {
				return false;
			}
			return true;
		}

		/**
		 * Extract the argument for this parameter
		 * 
		 * <p>
		 * You must validate the arguments, using
		 * {@link TraceMethod#validateArguments(Map, Map, boolean)}, first.
		 * 
		 * @param arguments the validated arguments
		 * @return the parameter
		 */
		@SuppressWarnings("unchecked")
		public T get(Map<String, ?> arguments) {
			if (arguments.containsKey(name)) {
				return (T) arguments.get(name);
			}
			if (required) {
				throw new IllegalArgumentException(
					"Missing required parameter '" + display + "' (" + name + ")");
			}
			return defaultValue;
		}

		/**
		 * Set the argument for this parameter
		 * 
		 * @param arguments the arguments to modify
		 * @param value the value to assign the parameter
		 */
		public void set(Map<String, ? super T> arguments, T value) {
			arguments.put(name, value);
		}

		/**
		 * Adjust the argument for this parameter
		 * 
		 * @param arguments the arguments to modify
		 * @param adjuster a function of the old argument to the new argument. If the argument is
		 *            not currently set, the function will receive null.
		 */
		@SuppressWarnings("unchecked")
		public void adjust(Map<String, ? super T> arguments, Function<T, T> adjuster) {
			arguments.put(name, adjuster.apply((T) arguments.get(name)));
		}

		@Override
		public String toString() {
			return String.format(
				"<ParameterDescription " + "name=%s type=%s default=%s required=%s " +
					"display='%s' description='%s' choices=%s",
				name, type, defaultValue, required, display, description, choices);
		}

	}

	/**
	 * Construct a map of parameter descriptions from a stream
	 * 
	 * @param params the descriptions
	 * @return a map of descriptions by name
	 */
	static Map<String, ParameterDescription<?>> makeParameters(
			Stream<ParameterDescription<?>> params) {
		return params.collect(Collectors.toMap(p -> p.name, p -> p, (a, b) -> {
			throw new IllegalArgumentException("duplicate parameters: " + a + " and " + b);
		}, LinkedHashMap::new));
	}

	/**
	 * Construct a map of parameter descriptions from a collection
	 * 
	 * @param params the descriptions
	 * @return a map of descriptions by name
	 */
	static Map<String, ParameterDescription<?>> makeParameters(
			Collection<ParameterDescription<?>> params) {
		return makeParameters(params.stream());
	}

	/**
	 * Construct a map of parameter descriptions from an array
	 * 
	 * @param params the descriptions
	 * @return a map of descriptions by name
	 */
	static Map<String, ParameterDescription<?>> makeParameters(ParameterDescription<?>... params) {
		return makeParameters(Stream.of(params));
	}

	/**
	 * Validate the given arguments against the given parameters
	 * 
	 * @param parameters the parameter descriptions
	 * @param arguments the arguments
	 * @param permitExtras false to require every named argument has a named parameter
	 * @return the map of validated arguments
	 */
	static Map<String, Object> validateArguments(Map<String, ParameterDescription<?>> parameters,
			Map<String, ?> arguments, boolean permitExtras) {
		if (!permitExtras) {
			if (!parameters.keySet().containsAll(arguments.keySet())) {
				Set<String> extraneous = new TreeSet<>(arguments.keySet());
				extraneous.removeAll(parameters.keySet());
				throw new IllegalArgumentException("Extraneous parameters: " + extraneous);
			}
		}
		Map<String, Object> valid = new LinkedHashMap<>();
		Map<String, String> typeErrors = null;
		Set<String> extraneous = null;
		for (Map.Entry<String, ?> ent : arguments.entrySet()) {
			String name = ent.getKey();
			Object val = ent.getValue();
			ParameterDescription<?> d = parameters.get(name);
			if (d == null && !permitExtras) {
				if (extraneous == null) {
					extraneous = new TreeSet<>();
				}
				extraneous.add(name);
			}
			else if (val != null && !d.type.isAssignableFrom(val.getClass())) {
				if (typeErrors == null) {
					typeErrors = new TreeMap<>();
				}
				typeErrors.put(name, "val '" + val + "' is not a " + d.type);
			}
			else {
				valid.put(name, val);
			}
		}
		if (typeErrors != null || extraneous != null) {
			StringBuilder sb = new StringBuilder();
			if (typeErrors != null) {
				sb.append("Type mismatches: ");
				sb.append(typeErrors);
			}
			if (extraneous != null) {
				sb.append("Extraneous parameters: ");
				sb.append(extraneous);
			}
			throw new IllegalArgumentException(sb.toString());
		}
		return valid;
	}
}
