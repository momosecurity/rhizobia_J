package com.immomo.rhizobia.rhizobia_J.extra.codecs;

import com.immomo.rhizobia.rhizobia_J.extra.commons.NullSafe;

import java.io.IOException;
import java.io.PushbackReader;
import java.util.*;

/**
 * Trie implementation for CharSequence keys. This uses HashMaps for each
 * level instead of the traditional array. This is done as with unicode,
 * each level's array would be 64k entries.
 *
 * <b>NOTE:</b><br>
 * <ul>
 *	<li>{@link Map.remove( Object )} is not supported.</li>
 *	<li>
 *		If deletion support is added the max key length will
 *		need work or removal.
 *	</li>
 *	<li>Null values are not supported.</li>
 * </ul>
 *
 * @author Ed Schaller
 */
public class HashTrie<T> implements Trie<T>
{
	private static class Entry<T> implements Map.Entry<CharSequence,T>
	{
		private CharSequence key;
		private T value;

		Entry(CharSequence key, T value)
		{
			this.key = key;
			this.value = value;
		}

		/**
		 * Convinence instantiator.
		 * @param key The key for the new instance
		 * @param keyLength The length of the key to use
		 * @param value The value for the new instance
		 * @return null if key or value is null
		 *	new Entry(key,value) if {@link CharSequence#length()} == keyLength
		 *	new Entry(key.subSequence(0,keyLength),value) otherwise
		 */
		static <T> Entry<T> newInstanceIfNeeded(CharSequence key, int keyLength, T value)
		{
			if(value == null || key == null)
				return null;
			if(key.length() > keyLength)
				key = key.subSequence(0,keyLength);
			return new Entry<T>(key,value);
		}

		/**
		 * Convinence instantiator.
		 * @param key The key for the new instance
		 * @param value The value for the new instance
		 * @return null if key or value is null
		 *	new Entry(key,value) otherwise
		 */
		static <T> Entry<T> newInstanceIfNeeded(CharSequence key, T value)
		{
			if(value == null || key == null)
				return null;
			return new Entry<T>(key,value);
		}

                /*************/
                /* Map.Entry */
                /*************/

		public CharSequence getKey()
		{
			return key;
		}

		public T getValue()
		{
			return value;
		}

		public T setValue(T value)
		{
			throw new UnsupportedOperationException();
		}

                /********************/
                /* java.lang.Object */
                /********************/

		public boolean equals(Map.Entry other)
		{
			return (NullSafe.equals(key, other.getKey()) && NullSafe.equals(value, other.getValue()));
		}

		@Override
		public boolean equals(Object o)
		{
			if(o instanceof Map.Entry)
				return equals((Map.Entry)o);
			return false;
		}

		@Override
		public int hashCode()
		{
			return NullSafe.hashCode(key) ^ NullSafe.hashCode(value);
		}

		@Override
		public String toString()
		{
			return NullSafe.toString(key) + " => " + NullSafe.toString(value);
		}
	}

	/**
	 * Node inside the trie.
	 */
	private static class Node<T>
	{
		private T value = null;
		private Map<Character,Node<T>> nextMap;

		/**
		 * Create a new Map for a node level. This is here so
		 * that if the underlying * Map implmentation needs to
		 * be switched it is easily done.
		 * @return A new Map for use.
		 */
		private static <T> Map<Character,Node<T>> newNodeMap()
		{
			return new HashMap<Character,Node<T>>();
		}

		/**
		 * Create a new Map for a node level. This is here so
		 * that if the underlying * Map implmentation needs to
		 * be switched it is easily done.
		 * @param prev Pervious map to use to populate the
		 * new map.
		 * @return A new Map for use.
		 */
		private static <T> Map<Character,Node<T>> newNodeMap(Map<Character,Node<T>> prev)
		{
			return new HashMap<Character,Node<T>>(prev);
		}

		/** 
		 * Set the value for the key terminated at this node.
		 * @param value The value for this key.
		 */
		void setValue(T value)
		{
			this.value = value;
		}

		/**
		 * Get the node for the specified character.
		 * @param ch The next character to look for.
		 * @return The node requested or null if it is not
		 *	present.
		 */
		Node<T> getNextNode(Character ch)
		{
			if(nextMap == null)
				return null;
			return nextMap.get(ch);
		}

		/**
		 * Recursively add a key.
		 * @param key The key being added.
		 * @param pos The position in key that is being handled
		 *	at this level.
		 */
		T put(CharSequence key, int pos, T addValue)
		{
			Node<T> nextNode;
			Character ch;
			T old;

			if(key.length() == pos)
			{	// at terminating node
				old = value;
				setValue(addValue);
				return old;
			}
			ch = key.charAt(pos);
			if(nextMap == null)
			{
				nextMap = newNodeMap();
				nextNode = new Node();
				nextMap.put(ch, nextNode);
			}
			else if((nextNode = nextMap.get(ch))==null)
			{
				nextNode = new Node();
				nextMap.put(ch,nextNode);
			}
			return nextNode.put(key,pos+1,addValue);
		}

		/**
		 * Recursively lookup a key's value.
		 * @param key The key being looked up.
		 * @param pos The position in the key that is being
		 *	looked up at this level.
		 * @return The value assocatied with the key or null if
		 *	none exists.
		 */
		T get(CharSequence key, int pos)
		{
			Node<T> nextNode;

			if(key.length() <= pos)	// <= instead of == just in case
				return value;	// no value is null which is also not found
			if((nextNode = getNextNode(key.charAt(pos)))==null)
				return null;
			return nextNode.get(key,pos+1);
		}
			
		/**
		 * Recursively lookup the longest key match.
		 * @param key The key being looked up.
		 * @param pos The position in the key that is being
		 *	looked up at this level.
		 * @return The Entry assocatied with the longest key
		 *	match or null if none exists.
		 */
		Entry<T> getLongestMatch(CharSequence key, int pos)
		{
			Node<T> nextNode;
			Entry<T> ret;

			if(key.length() <= pos)	// <= instead of == just in case
				return Entry.newInstanceIfNeeded(key,value);
			if((nextNode = getNextNode(key.charAt(pos)))==null)
			{	// last in trie... return ourselves
				return Entry.newInstanceIfNeeded(key,pos,value);
			}
			if((ret = nextNode.getLongestMatch(key, pos+1))!=null)
				return ret;
			return Entry.newInstanceIfNeeded(key,pos,value);
		}

		/**
		 * Recursively lookup the longest key match.
		 * @param keyIn Where to read the key from
		 * @param pos The position in the key that is being
		 *	looked up at this level.
		 * @return The Entry assocatied with the longest key
		 *	match or null if none exists.
		 */
		Entry<T> getLongestMatch(PushbackReader keyIn, StringBuilder key) throws IOException
		{
			Node<T> nextNode;
			Entry<T> ret;
			int c;
			char ch;
			int prevLen;

			// read next key char and append to key...
			if((c = keyIn.read())<0)
				// end of input, return what we have currently
				return Entry.newInstanceIfNeeded(key,value);
			ch = (char)c;
			prevLen = key.length();
			key.append(ch);

			if((nextNode = getNextNode(ch))==null)
			{	// last in trie... return ourselves
				return Entry.newInstanceIfNeeded(key,value);
			}
			if((ret = nextNode.getLongestMatch(keyIn, key))!=null)
				return ret;

			// undo reading of key char and appending to key...
			key.setLength(prevLen);
			keyIn.unread(c);

			return Entry.newInstanceIfNeeded(key,value);
		}

		/**
		 * Recursively rebuild the internal maps.
		 */
		void remap()
		{
			if(nextMap == null)
				return;
			nextMap = newNodeMap(nextMap);
			for(Node<T> node : nextMap.values())
				node.remap();
		}

		/**
		 * Recursively search for a value.
		 * @param toFind The value to search for
		 * @return true if the value was found
		 *	false otherwise
		 */
		boolean containsValue(Object toFind)
		{
			if(value != null && toFind.equals(value))
				return true;
			if(nextMap == null)
				return false;
			for(Node<T> node : nextMap.values())
				if(node.containsValue(toFind))
					return true;
			return false;
		}

		/**
		 * Recursively build values.
		 * @param values List being built.
		 * @return true if the value was found
		 *	false otherwise
		 */
		Collection<T> values(Collection<T> values)
		{
			if(value != null)
				values.add(value);
			if(nextMap == null)
				return values;
			for(Node<T> node : nextMap.values())
				node.values(values);
			return values;
		}

		/**
		 * Recursively build a key set.
		 * @param key StringBuilder with our key.
		 * @param keys Set to add to
		 * @return keys with additions
		 */
		Set<CharSequence> keySet(StringBuilder key, Set<CharSequence> keys)
		{
			int len = key.length();

			if(value != null)
				// MUST toString here
				keys.add(key.toString());
			if(nextMap != null && nextMap.size() > 0)
			{
				key.append('X');
				for(Map.Entry<Character,Node<T>> entry : nextMap.entrySet())
				{
					key.setCharAt(len,entry.getKey());
					entry.getValue().keySet(key,keys);
				}
				key.setLength(len);
			}
			return keys;
		}

		/**
		 * Recursively build a entry set.
		 * @param key StringBuilder with our key.
		 * @param entries Set to add to
		 * @return entries with additions
		 */
		Set<Map.Entry<CharSequence,T>> entrySet(StringBuilder key, Set<Map.Entry<CharSequence,T>> entries)
		{
			int len = key.length();

			if(value != null)
				// MUST toString here
				entries.add(new Entry(key.toString(),value));
			if(nextMap != null && nextMap.size() > 0)
			{
				key.append('X');
				for(Map.Entry<Character,Node<T>> entry : nextMap.entrySet())
				{
					key.setCharAt(len,entry.getKey());
					entry.getValue().entrySet(key,entries);
				}
				key.setLength(len);
			}
			return entries;
		}
	}

	private Node<T> root;
	private int maxKeyLen;
	private int size;

	public HashTrie()
	{
		clear();
	}

	/**
	 * Get the key value entry who's key is the longest prefix match.
	 * @param key The key to lookup
	 * @return Entry with the longest matching key.
	 */
	public Map.Entry<CharSequence,T> getLongestMatch(CharSequence key)
	{
		if(root == null || key == null)
			return null;
		return root.getLongestMatch(key, 0);
	}

	/**
	 * Get the key value entry who's key is the longest prefix match.
	 * @param keyIn Pushback reader to read the key from. This should
	 * have a buffer at least as large as {@link #getMaxKeyLength()}
	 * or an IOException may be thrown backing up.
	 * @return Entry with the longest matching key.
	 * @throws IOException if keyIn.read() or keyIn.unread() does.
	 */
	public Map.Entry<CharSequence,T> getLongestMatch(PushbackReader keyIn) throws IOException
	{
		if(root == null || keyIn == null)
			return null;
		return root.getLongestMatch(keyIn, new StringBuilder());
	}

	/**
	 * Get the maximum key length.
	 * @return max key length.
	 */
	public int getMaxKeyLength()
	{
		return maxKeyLen;
	}

        /*****************/
        /* java.util.Map */
        /*****************/

	/**
	 * Clear all entries.
	 */
	public void clear()
	{
		root = null;
		maxKeyLen = -1;
		size = 0;
	}

	/** {@inheritDoc} */
	public boolean containsKey(Object key)
	{
		return (get(key) != null);
	}

	/** {@inheritDoc} */
	public boolean containsValue(Object value)
	{
		if(root == null)
			return false;
		return root.containsValue(value);
	}

	/**
	 * Add mapping.
	 * @param key The mapping's key.
	 * @value value The mapping's value
	 * @throws NullPointerException if key or value is null.
	 */
	public T put(CharSequence key, T value) throws NullPointerException
	{
		int len;
		T old;

		if(key == null)
			throw new NullPointerException("Null keys are not handled");
		if(value == null)
			throw new NullPointerException("Null values are not handled");
		if(root == null)
			root = new Node<T>();
		if((old = root.put(key,0,value))!=null)
			return old;

		// after in case of replacement
		if((len = key.length()) > maxKeyLen)
			maxKeyLen = len;
		size++;
		return null;
	}

	/**
	 * Remove a entry.
	 * @return previous value
	 * @throws UnsupportedOperationException always.
	 */
	public T remove(Object key) throws UnsupportedOperationException
	{
		throw new UnsupportedOperationException();
	}

	/** {@inheritDoc} */
	public void putAll(Map<? extends CharSequence, ? extends T> map)
	{
		for(Map.Entry<? extends CharSequence, ? extends T> entry : map.entrySet())
			put(entry.getKey(),entry.getValue());
	}

	/** {@inheritDoc} */
	public Set<CharSequence> keySet()
	{
		Set<CharSequence> keys = new HashSet<CharSequence>(size);
		
		if(root == null)
			return keys;
		return root.keySet(new StringBuilder(), keys);
	}

	/** {@inheritDoc} */
	public Collection<T> values()
	{
		ArrayList<T> values = new ArrayList<T>(size());

		if(root == null)
			return values;
		return root.values(values);
	}

	/** {@inheritDoc} */
	public Set<Map.Entry<CharSequence,T>> entrySet()
	{
		Set<Map.Entry<CharSequence,T>> entries = new HashSet<Map.Entry<CharSequence,T>>(size());

		if(root == null)
			return entries;
		return root.entrySet(new StringBuilder(), entries);
	}

	/**
	 * Get the value for a key.
	 * @param key The key to look up.
	 * @return The value for key or null if the key is not found.
	 */
	public T get(Object key)
	{
		if(root == null || key == null)
			return null;
		if(!(key instanceof CharSequence))
			return null;
		return root.get((CharSequence)key,0);
	}

	/**
	 * Get the number of entries.
	 * @return the number or entries.
	 */
	public int size()
	{
		return size;
	}

	/** {@inheritDoc} */
	@Override
	public boolean equals(Object other)
	{
		if(other == null)
			return false;
		if(!(other instanceof Map))
			return false;
		// per spec
		return entrySet().equals(((Map)other).entrySet());
	}

	/** {@inheritDoc} */
	@Override
	public int hashCode()
	{
		// per spec
		return entrySet().hashCode();
	}

	/** {@inheritDoc} */
	@Override
	public String toString()
	{
		StringBuilder sb;
		boolean first;

		if(isEmpty())
			return "{}";
		sb = new StringBuilder();
		first = true;
		sb.append("{ ");
		for(Map.Entry<CharSequence,T> entry : entrySet())
		{
			if(first)
				first = false;
			else
				sb.append(", ");
			sb.append(entry.toString());
		}
		sb.append(" }");
		return sb.toString();
	}

	/** {@inheritDoc} */
	public boolean isEmpty()
	{
		return(size() == 0);
	}
}
