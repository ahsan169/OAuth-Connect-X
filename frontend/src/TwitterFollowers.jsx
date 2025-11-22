import { useState, useEffect } from "react";
import "./App.css";

export function TwitterFollowers() {
  const [followers, setFollowers] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchFollowers();
  }, []);

  const fetchFollowers = async () => {
    try {
      setLoading(true);
      const response = await fetch(
        "http://localhost:3000/api/twitter/followers",
        {
          credentials: "include",
        }
      );

      if (!response.ok) {
        throw new Error("Failed to fetch followers");
      }

      const data = await response.json();
      setFollowers(data.data || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <div className="text-gray-600">Loading followers...</div>;
  if (error) return <div className="text-red-600">Error: {error}</div>;

  return (
    <div className="mt-6 border-t border-gray-200 pt-6">
      <h3 className="text-xl font-bold mb-4">Your Followers</h3>
      <div className="flex justify-between items-center mb-4">
        <h3 className="text-xl font-bold">Your Followers</h3>
        <button
          onClick={fetchFollowers}
          className="text-sm text-blue-500 hover:text-blue-600"
        >
          Refresh
        </button>
      </div>
      {followers.length === 0 ? (
        <p className="text-gray-600">No followers found</p>
      ) : (
        <div className="space-y-4 max-h-64 overflow-y-auto">
          {followers.map((follower) => (
            <div
              key={follower.id}
              className="flex items-center space-x-3 p-2 hover:bg-gray-50 rounded"
            >
              <div>
                <div className="font-medium">{follower.name}</div>
                <div className="text-sm text-gray-500">
                  @{follower.username}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
