import { useState, useEffect } from "react";
import "./App.css";
import { TwitterFollowers } from "./TwitterFollowers";
import { TwitterFollowing } from "./TwitterFollowing";

function App() {
  const [twitterConnection, setTwitterConnection] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    checkConnection();
  }, []);

  const checkConnection = async () => {
    try {
      const response = await fetch(
        "http://localhost:3000/api/connections/twitter",
        {
          credentials: "include",
        }
      );
      if (response.ok) {
        const data = await response.json();
        setTwitterConnection(data);
      }
    } catch (err) {
      setError("Failed to check connection status");
    } finally {
      setLoading(false);
    }
  };

  const handleConnect = () => {
    window.location.href = "http://localhost:3000/connect/twitter";
  };

  const handleDisconnect = async () => {
    try {
      const response = await fetch("http://localhost:3000/disconnect/twitter", {
        method: "POST",
        credentials: "include",
      });
      if (response.ok) {
        setTwitterConnection({ connected: false, data: null });
      }
    } catch (err) {
      setError("Failed to disconnect");
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-100 flex items-center justify-center">
        Loading...
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-100 py-6 flex flex-col justify-center sm:py-12">
      <div className="relative py-3 sm:max-w-xl sm:mx-auto">
        <div className="absolute inset-0 bg-gradient-to-r from-cyan-400 to-light-blue-500 shadow-lg transform -skew-y-6 sm:skew-y-0 sm:-rotate-6 sm:rounded-3xl"></div>
        <div className="relative px-4 py-10 bg-white shadow-lg sm:rounded-3xl sm:p-20">
          <div className="max-w-md mx-auto">
            <div className="divide-y divide-gray-200">
              <div className="py-8 text-base leading-6 space-y-4 text-gray-700 sm:text-lg sm:leading-7">
                <h2 className="text-2xl font-bold mb-8 text-center">
                  Twitter Connection
                </h2>

                {error && (
                  <div className="mb-4 p-4 bg-red-100 text-red-700 rounded">
                    {error}
                  </div>
                )}

                {twitterConnection?.connected ? (
                  <div className="space-y-6">
                    <div className="flex items-center space-x-4">
                      {twitterConnection.data.profileImageUrl && (
                        <img
                          src={twitterConnection.data.profileImageUrl}
                          alt="Profile"
                          className="w-12 h-12 rounded-full"
                        />
                      )}
                      <div>
                        <div className="font-bold">
                          {twitterConnection.data.displayName}
                        </div>
                        <div className="text-gray-600">
                          @{twitterConnection.data.username}
                        </div>
                      </div>
                    </div>

                    <div className="text-sm text-gray-600">
                      Connected on:{" "}
                      {new Date(
                        twitterConnection.data.connectedAt
                      ).toLocaleDateString()}
                    </div>

                    <TwitterFollowers />
                    <TwitterFollowing />

                    <button
                      onClick={handleDisconnect}
                      className="w-full py-2 px-4 bg-red-500 text-white rounded hover:bg-red-600 transition-colors"
                    >
                      Disconnect Twitter
                    </button>
                  </div>
                ) : (
                  <div className="space-y-6">
                    <button
                      onClick={handleConnect}
                      className="w-full py-2 px-4 bg-blue-500 text-white rounded hover:bg-blue-600 transition-colors"
                    >
                      Connect Twitter
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
