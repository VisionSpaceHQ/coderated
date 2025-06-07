// src/components/Dashboard.jsx
import React, { useEffect, useState } from "react";
import WebsiteCard from "./WebsiteCard.jsx";
import SearchSection from "./SearchSection.jsx";
import api from "../utils/api.js";

export default function Dashboard() {
  const [sites, setSites] = useState([]);
  const [loading, setLoading] = useState(false);
  const [pagination, setPagination] = useState({ page: 1, size: 20, total: 0 });

  const fetchSites = async (params = {}) => {
    setLoading(true);
    try {
      const response = await api.get("/sites", {
        params: {
          page: pagination.page,
          size: pagination.size,
          ...params, // e.g. { search: "keyword" }
        },
      });
      const { sites: siteList, pagination: pag } = response.data;
      setSites(siteList);
      setPagination((prev) => ({ ...prev, total: pag.total }));
    } catch (err) {
      console.error("Error fetching sites:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // Initial fetch, no filters
    fetchSites();
  }, []);

  // Handler when SearchSection triggers a search
  const handleSearch = (searchTerm) => {
    fetchSites({ search: searchTerm, page: 1 });
  };

  return (
    <div className="dashboard-container">
      <SearchSection onSearch={handleSearch} />

      {loading && <div className="loading-indicator">Loading…</div>}

      {!loading && sites.length === 0 && (
        <div className="no-results">No sites found.</div>
      )}

      <div className="site-list">
        {sites.map((site) => (
          <WebsiteCard key={site.id} site={site} />
        ))}
      </div>

      {/* Pagination controls (if you want): 
          <Pagination 
            current={pagination.page} 
            total={pagination.total} 
            pageSize={pagination.size} 
            onChange={(newPage) => setPagination({...}); fetchSites({ page: newPage });} 
          /> 
      */}
    </div>
  );
}
