interface ActivityItem {
  id: number;
  type: "scan" | "alert" | "system";
  email?: string;
  result?: "phishing" | "suspicious" | "benign";
  message?: string;
  timestamp: string;
}

interface ActivityFeedProps {
  activities: ActivityItem[];
  title?: string;
}

export default function ActivityFeed({ activities, title = "Recent Activity" }: ActivityFeedProps) {
  const getResultBadge = (result: string) => {
    const styles = {
      phishing: "bg-red-100 text-red-700 border-red-200",
      suspicious: "bg-yellow-100 text-yellow-700 border-yellow-200",
      benign: "bg-green-100 text-green-700 border-green-200"
    };
    return `inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium ${styles[result as keyof typeof styles] || styles.benign}`;
  };

  const getActivityIcon = (type: string) => {
    switch (type) {
      case "scan":
        return (
          <svg className="h-4 w-4 text-blue-600 dark:text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 4.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
          </svg>
        );
      case "alert":
        return (
          <svg className="h-4 w-4 text-red-600 dark:text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.732-.833-2.5 0L4.268 18.5c-.77.833.192 2.5 1.732 2.5z" />
          </svg>
        );
      case "system":
        return (
          <svg className="h-4 w-4 text-purple-600 dark:text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z" />
          </svg>
        );
      default:
        return (
          <svg className="h-4 w-4 text-slate-600 dark:text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        );
    }
  };

  const getIconBgColor = (type: string) => {
    switch (type) {
      case "scan":
        return "bg-blue-100 dark:bg-blue-900/20";
      case "alert":
        return "bg-red-100 dark:bg-red-900/20";
      case "system":
        return "bg-purple-100 dark:bg-purple-900/20";
      default:
        return "bg-slate-100 dark:bg-slate-900/20";
    }
  };

  return (
    <section className="rounded-2xl border bg-white/60 dark:bg-slate-900/40 backdrop-blur p-6 shadow-sm">
      <h2 className="text-lg font-semibold mb-4">{title}</h2>
      <div className="space-y-3">
        {activities.map((activity) => (
          <div key={activity.id} className="flex items-center justify-between p-3 rounded-lg bg-slate-50 dark:bg-slate-800/50">
            <div className="flex items-center gap-3">
              <div className={`rounded-full p-2 ${getIconBgColor(activity.type)}`}>
                {getActivityIcon(activity.type)}
              </div>
              <div>
                <p className="text-sm font-medium text-slate-900 dark:text-slate-100">
                  {activity.email || activity.message || "System Activity"}
                </p>
                <p className="text-xs text-slate-500 dark:text-slate-400">{activity.timestamp}</p>
              </div>
            </div>
            {activity.result && (
              <span className={getResultBadge(activity.result)}>
                {activity.result}
              </span>
            )}
          </div>
        ))}
      </div>
    </section>
  );
}
