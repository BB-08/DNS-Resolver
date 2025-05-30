import { useState } from 'react';

function App() {
  const [hostname, setHostname] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchData = async () => {
    if (!hostname) return;

    setLoading(true);
    try {
      const res = await fetch(
        `http://127.0.0.1:5000/resolve?hostname=${hostname}`
      );
      const data = await res.json();
      setResult(data);
    } catch (error) {
      console.error(error);
      setResult({ error: 'Error fetching data.' });
    }
    setLoading(false);
  };

  return (
    <div className='min-h-screen flex flex-col items-center p-8'>
      <h1 className='text-3xl font-bold text-gray-800 mb-4'>DNS Resolver</h1>

      <div className='flex gap-2 mb-4'>
        <input
          type='text'
          placeholder='example.com'
          value={hostname}
          onChange={(e) => setHostname(e.target.value)}
          className='p-2 border border-gray-300 rounded bg-white focus:outline-none'
        />
        <button
          onClick={fetchData}
          className='bg-gray-800 text-white px-4 py-2 rounded hover:bg-gray-700 transition'
        >
          Resolve
        </button>
      </div>

      {loading && <p className='text-gray-600'>Resolving...</p>}

      {result && (
        <div className='mt-4 bg-white rounded shadow p-4 w-full max-w-md'>
          {result.error ? (
            <p className='text-red-500'>{result.error}</p>
          ) : (
            <>
              <h2 className='text-lg font-semibold mb-2'>{result.hostname}</h2>
              <div className='mb-2'>
                <strong>Flags:</strong>{' '}
                <span className='text-sm text-gray-600'>
                  AA: {result.flags.AA ? '✅' : '❌'}, TC:{' '}
                  {result.flags.TC ? '✅' : '❌'}, RCODE: {result.flags.RCODE}
                </span>
              </div>
              <div>
                <strong>IP Addresses:</strong>
                <ul className='list-disc ml-6 mt-1 text-sm text-gray-700'>
                  {result.ip_addresses.map((ip, i) => (
                    <li key={i}>{ip}</li>
                  ))}
                </ul>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

export default App;
