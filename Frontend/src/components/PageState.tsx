import { AlertTriangle, Inbox, LoaderCircle } from "lucide-react";

export function LoadingState({ label = "Loading security data" }: { label?: string }) {
  return (
    <div className="page-state" role="status">
      <LoaderCircle className="spin" size={28} />
      <p>{label}</p>
    </div>
  );
}

export function ErrorState({ message, retry }: { message: string; retry?: () => void }) {
  return (
    <div className="page-state error-state" role="alert">
      <AlertTriangle size={28} />
      <p>{message}</p>
      {retry && <button onClick={retry}>Try again</button>}
    </div>
  );
}

export function EmptyState({ message }: { message: string }) {
  return (
    <div className="page-state compact">
      <Inbox size={26} />
      <p>{message}</p>
    </div>
  );
}
