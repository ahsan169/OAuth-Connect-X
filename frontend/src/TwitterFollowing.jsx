import { useState, useEffect } from "react";

export function TwitterFollowing() {
  const [following, setFollowing] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchFollowing();
  }, []);

  const fetchFollowing = async () => {
    try {
      setLoading(true);
      const response = await fetch(
        "http://localhost:3000/api/twitter/following",
        {
          credentials: "include",
        }
      );

      if (!response.ok) {
        throw new Error("Failed to fetch following");
      }

      const data = await response.json();
      setFollowing(data.data || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <div className="text-gray-600">Loading following...</div>;
  if (error) return <div className="text-red-600">Error: {error}</div>;

  return (
    <div className="mt-6 border-t border-gray-200 pt-6">
      <div className="flex justify-between items-center mb-4">
        <h3 className="text-xl font-bold">Accounts You Follow</h3>
        <button
          onClick={fetchFollowing}
          className="text-sm text-blue-500 hover:text-blue-600"
        >
          Refresh
        </button>
      </div>
      {following.length === 0 ? (
        <p className="text-gray-600">No following found</p>
      ) : (
        <div className="space-y-4 max-h-64 overflow-y-auto">
          {following.map((user) => (
            <div
              key={user.id}
              className="flex items-center space-x-3 p-2 hover:bg-gray-50 rounded"
            >
              <div>
                <div className="font-medium">{user.name}</div>
                <div className="text-sm text-gray-500">@{user.username}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
