import { useEffect, useState } from "react";
import axios from "axios";

export default function App() {
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    const interval = setInterval(() => {
      const API = `http://${window.location.hostname}:5000`;

      axios.get(`${API}/alerts`)
        .then(res => {
          console.log("DATA:", res.data);
          setAlerts(res.data);
        })
        .catch(err => console.error(err));
    }, 2000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ padding: "20px" }}>
      <h1>JA3 Threat Dashboard</h1>

      <table border="1">
        <thead>
          <tr>
            <th>Source</th>
            <th>Dest</th>
            <th>JA3</th>
            <th>Status</th>
          </tr>
        </thead>

        <tbody>
          {alerts.map((a, i) => (
            <tr key={i}>
              <td>{a.src}</td>
              <td>{a.dst}</td>
              <td>{a.ja3}</td>
              <td>{a.threat}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
