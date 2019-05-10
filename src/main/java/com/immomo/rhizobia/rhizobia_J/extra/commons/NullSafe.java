package com.immomo.rhizobia.rhizobia_J.extra.commons;

public class NullSafe
{
	/**
	 * Class should not be instantiated.
	 */
	private NullSafe()
	{
	}

	/**
	 * {@link Object#equals(Object)} that safely handles nulls.
	 * @param a First object
	 * @param b Second object
	 * @return true if a == b or a.equals(b). false otherwise.
	 */
	public static boolean equals(Object a, Object b)
	{
		if(a==b)	// short cut same object
			return true;
		if(a == null)
			return (b == null);
		if(b == null)
			return false;
		return a.equals(b);
	}

	/**
	 * {@link Object#hashCode()} of an object.
	 * @param o Object to get a hashCode for.
	 * @return 0 if o is null. Otherwise o.hashCode().
	 */
	public static int hashCode(Object o)
	{
		if(o == null)
			return 0;
		return o.hashCode();
	}

	/**
	 * {@link Object#toString()} of an object.
	 * @param o Object to get a String for.
	 * @return "(null)" o is null. Otherwise o.toString().
	 */
	public static String toString(Object o)
	{
		if(o == null)
			return "(null)";
		return o.toString();
	}
}
