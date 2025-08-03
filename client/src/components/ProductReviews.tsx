import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Star, ThumbsUp, User, Calendar, Edit2, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { StarRating } from "@/components/ui/star-rating";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";

interface Review {
  id: number;
  rating: number;
  title?: string;
  comment?: string;
  createdAt: string;
  isVerifiedPurchase: boolean;
  helpfulCount: number;
  customer?: {
    id: number;
    username: string;
    fullName: string;
  };
}

interface ProductReviewsProps {
  productId: number;
  productName: string;
}

export function ProductReviews({ productId, productName }: ProductReviewsProps) {
  const [showReviewForm, setShowReviewForm] = useState(false);
  const [reviewData, setReviewData] = useState({
    rating: 0,
    title: "",
    comment: ""
  });
  const [filterRating, setFilterRating] = useState<number | null>(null);

  const { user } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: reviews = [], isLoading } = useQuery({
    queryKey: ["/api/products", productId, "reviews", { minRating: filterRating }],
    queryFn: async () => {
      const response = await fetch(`/api/products/${productId}/reviews${filterRating ? `?minRating=${filterRating}` : ""}`);
      const data = await response.json();
      // Ensure we always return an array
      return Array.isArray(data) ? data : [];
    }
  });

  const createReviewMutation = useMutation({
    mutationFn: (reviewData: any) => 
      apiRequest("/api/reviews", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(reviewData)
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/products", productId, "reviews"] });
      setShowReviewForm(false);
      setReviewData({ rating: 0, title: "", comment: "" });
      toast({
        title: "Review submitted",
        description: "Your review has been posted successfully!"
      });
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to submit review",
        variant: "destructive"
      });
    }
  });

  const markHelpfulMutation = useMutation({
    mutationFn: (reviewId: number) => 
      apiRequest(`/api/reviews/${reviewId}/helpful`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ userId: user?.id || 9 }) // Use logged in user or default for testing
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/products", productId, "reviews"] });
      toast({
        title: "Thank you!",
        description: "Review marked as helpful"
      });
    },
    onError: (error: any) => {
      const errorMessage = error?.error || error?.message || "Failed to mark review as helpful";
      toast({
        title: "Error",
        description: errorMessage,
        variant: "destructive"
      });
    }
  });

  const handleSubmitReview = () => {
    if (!user) {
      toast({
        title: "Login required",
        description: "Please login to submit a review",
        variant: "destructive"
      });
      return;
    }

    if (reviewData.rating === 0) {
      toast({
        title: "Rating required",
        description: "Please provide a rating",
        variant: "destructive"
      });
      return;
    }

    const reviewPayload = {
      productId,
      customerId: user.id,
      rating: reviewData.rating,
      title: reviewData.title || null,
      comment: reviewData.comment || null
    };

    console.log("Submitting review with payload:", reviewPayload);
    createReviewMutation.mutate(reviewPayload);
  };

  const averageRating = reviews.length > 0 
    ? reviews.reduce((sum: number, review: Review) => sum + review.rating, 0) / reviews.length 
    : 0;

  const ratingCounts = [5, 4, 3, 2, 1].map(rating => ({
    rating,
    count: reviews.filter((review: Review) => review.rating === rating).length,
    percentage: reviews.length > 0 
      ? (reviews.filter((review: Review) => review.rating === rating).length / reviews.length) * 100 
      : 0
  }));

  // Check if current user already reviewed this product
  const userHasReviewed = user && reviews.some((review: Review) => review.customer?.id === user.id);

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="animate-pulse">
          <div className="h-4 bg-gray-200 rounded w-1/4 mb-2"></div>
          <div className="h-20 bg-gray-200 rounded"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Rating Summary */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-lg">Customer Reviews</CardTitle>
        </CardHeader>
        <CardContent className="pt-0">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Overall Rating */}
            <div className="text-center">
              <div className="text-2xl font-bold text-gray-900 dark:text-white mb-1">
                {averageRating.toFixed(1)}
              </div>
              <StarRating rating={averageRating} readonly size="md" className="justify-center mb-1" />
              <p className="text-xs text-gray-600 dark:text-gray-400">
                {reviews.length} review{reviews.length !== 1 ? 's' : ''}
              </p>
            </div>

            {/* Rating Breakdown */}
            <div className="space-y-1">
              {ratingCounts.map(({ rating, count, percentage }) => (
                <div key={rating} className="flex items-center gap-2">
                  <span className="text-xs w-6">{rating}</span>
                  <Star className="h-3 w-3 fill-yellow-400 text-yellow-400" />
                  <div className="flex-1 bg-gray-200 dark:bg-gray-700 rounded-full h-1.5">
                    <div 
                      className="bg-yellow-400 h-1.5 rounded-full" 
                      style={{ width: `${percentage}%` }}
                    />
                  </div>
                  <span className="text-xs text-gray-600 dark:text-gray-400 w-8">
                    {count}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Filter Controls */}
          <div className="flex flex-wrap gap-1 mt-3">
            <Button
              variant={filterRating === null ? "default" : "outline"}
              size="sm"
              className="h-7 px-3 text-xs"
              onClick={() => setFilterRating(null)}
            >
              All
            </Button>
            {[5, 4, 3, 2, 1].map(rating => (
              <Button
                key={rating}
                variant={filterRating === rating ? "default" : "outline"}
                size="sm"
                className="h-7 px-3 text-xs"
                onClick={() => setFilterRating(rating)}
              >
                {rating}★
              </Button>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Write Review Section */}
      {user && !userHasReviewed && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Write a Review</CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            {!showReviewForm ? (
              <Button onClick={() => setShowReviewForm(true)}>
                Write a Review
              </Button>
            ) : (
              <div className="space-y-3">
                <div>
                  <label className="block text-xs font-medium mb-1">
                    Rating *
                  </label>
                  <StarRating
                    rating={reviewData.rating}
                    onRatingChange={(rating) => setReviewData(prev => ({ ...prev, rating }))}
                    size="md"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium mb-1">
                    Title (Optional)
                  </label>
                  <Input
                    placeholder="Summarize your review..."
                    value={reviewData.title}
                    onChange={(e) => setReviewData(prev => ({ ...prev, title: e.target.value }))}
                    className="h-8"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium mb-1">
                    Review (Optional)
                  </label>
                  <Textarea
                    placeholder={`Share your thoughts about ${productName}...`}
                    value={reviewData.comment}
                    onChange={(e) => setReviewData(prev => ({ ...prev, comment: e.target.value }))}
                    rows={3}
                    className="text-sm"
                  />
                </div>

                <div className="flex gap-2">
                  <Button 
                    onClick={handleSubmitReview}
                    disabled={createReviewMutation.isPending || reviewData.rating === 0}
                  >
                    {createReviewMutation.isPending ? "Submitting..." : "Submit Review"}
                  </Button>
                  <Button 
                    variant="outline" 
                    onClick={() => {
                      setShowReviewForm(false);
                      setReviewData({ rating: 0, title: "", comment: "" });
                    }}
                  >
                    Cancel
                  </Button>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Existing Reviews */}
      <div className="space-y-3">
        {reviews.length === 0 ? (
          <Card>
            <CardContent className="text-center py-6">
              <p className="text-gray-500 dark:text-gray-400 text-sm">
                No reviews yet. Be the first to review this product!
              </p>
            </CardContent>
          </Card>
        ) : (
          reviews.map((review: Review) => (
            <Card key={review.id}>
              <CardContent className="pt-4 pb-4">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <div className="h-8 w-8 bg-gray-200 dark:bg-gray-700 rounded-full flex items-center justify-center">
                      <User className="h-4 w-4 text-gray-600 dark:text-gray-400" />
                    </div>
                    <div>
                      <p className="font-medium text-sm">
                        {review.customer?.fullName || review.customer?.username || "Anonymous"}
                      </p>
                      <div className="flex items-center gap-2 text-xs text-gray-600 dark:text-gray-400">
                        <Calendar className="h-3 w-3" />
                        {new Date(review.createdAt).toLocaleDateString()}
                        {review.isVerifiedPurchase && (
                          <Badge variant="secondary" className="text-xs h-4">
                            Verified
                          </Badge>
                        )}
                      </div>
                    </div>
                  </div>
                  <StarRating rating={review.rating} readonly size="sm" />
                </div>

                {review.title && (
                  <h4 className="font-medium text-sm mb-2">{review.title}</h4>
                )}

                {review.comment && (
                  <p className="text-gray-700 dark:text-gray-300 mb-3 text-sm leading-relaxed">
                    {review.comment}
                  </p>
                )}

                <div className="flex items-center gap-4 text-xs">
                  <button 
                    onClick={() => markHelpfulMutation.mutate(review.id)}
                    disabled={markHelpfulMutation.isPending}
                    className="flex items-center gap-1 text-gray-600 dark:text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 disabled:opacity-50 transition-colors"
                  >
                    <ThumbsUp className="h-3 w-3" />
                    {markHelpfulMutation.isPending ? "..." : `Helpful (${review.helpfulCount})`}
                  </button>
                </div>
              </CardContent>
            </Card>
          ))
        )}
      </div>
    </div>
  );
}