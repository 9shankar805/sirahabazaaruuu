import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Badge } from '@/components/ui/badge';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useToast } from '@/hooks/use-toast';
import { Star, ThumbsUp, MessageCircle, Shield, User } from 'lucide-react';
import { StarRating } from '@/components/ui/star-rating';
import { apiRequest } from '@/lib/queryClient';

const reviewSchema = z.object({
  rating: z.number().min(1).max(5),
  title: z.string().optional(),
  comment: z.string().optional(),
});

type ReviewFormData = z.infer<typeof reviewSchema>;

interface StoreReview {
  id: number;
  storeId: number;
  customerId: number;
  rating: number;
  title: string | null;
  comment: string | null;
  isVerifiedPurchase: boolean;
  isApproved: boolean;
  helpfulCount: number;
  createdAt: string;
  customer: {
    id: number;
    username: string;
    fullName: string;
  } | null;
}

interface StoreReviewsProps {
  storeId: number;
  currentUserId?: number;
}

export default function StoreReviews({ storeId, currentUserId }: StoreReviewsProps) {
  const [isReviewDialogOpen, setIsReviewDialogOpen] = useState(false);
  const [selectedRating, setSelectedRating] = useState<number>(0);
  const [showAllReviews, setShowAllReviews] = useState(false);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const form = useForm<ReviewFormData>({
    resolver: zodResolver(reviewSchema),
    defaultValues: {
      rating: 0,
      title: '',
      comment: '',
    },
  });

  // Fetch store reviews
  const { data: reviewsData, isLoading } = useQuery({
    queryKey: ['/api/stores', storeId, 'reviews'],
    queryFn: async () => {
      const response = await apiRequest(`/api/stores/${storeId}/reviews`);
      return await response.json();
    },
  });

  // Ensure reviews is always an array
  const reviews = Array.isArray(reviewsData) ? reviewsData : [];

  // Sort reviews by creation date (newest first) and limit display
  const sortedReviews = reviews.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  const displayedReviews = showAllReviews ? sortedReviews : sortedReviews.slice(0, 2);

  // Create review mutation
  const createReviewMutation = useMutation({
    mutationFn: (data: any) => 
      apiRequest('/api/store-reviews', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      toast({
        title: "Review submitted successfully",
        description: "Thank you for your feedback!",
      });
      setIsReviewDialogOpen(false);
      form.reset();
      setSelectedRating(0);
      
      // Comprehensive cache invalidation to ensure store ratings update immediately
      queryClient.invalidateQueries({ queryKey: ['/api/stores', storeId, 'reviews'] });
      queryClient.invalidateQueries({ queryKey: ['/api/stores'] });
      queryClient.invalidateQueries({ queryKey: [`/api/stores/${storeId}`] });
      
      // Force immediate cache removal and refetch
      queryClient.removeQueries({ queryKey: ['/api/stores'] });
      queryClient.removeQueries({ queryKey: [`/api/stores/${storeId}`] });
      
      // Delay slightly then force fresh fetch to allow server update to complete
      setTimeout(() => {
        queryClient.refetchQueries({ queryKey: ['/api/stores'] });
        queryClient.refetchQueries({ queryKey: [`/api/stores/${storeId}`] });
        queryClient.refetchQueries({ queryKey: ['/api/stores', storeId, 'reviews'] });
      }, 1000);
    },
    onError: (error: any) => {
      const isAlreadyReviewed = error.message?.includes("already reviewed");
      
      toast({
        title: isAlreadyReviewed ? "Review Already Submitted" : "Error submitting review",
        description: isAlreadyReviewed 
          ? "You have already reviewed this store. You can only submit one review per store."
          : error.message || "Failed to submit your review. Please try again.",
        variant: isAlreadyReviewed ? "default" : "destructive",
      });
    },
  });

  // Mark review as helpful mutation
  const markHelpfulMutation = useMutation({
    mutationFn: (reviewId: number) => 
      apiRequest(`/api/store-reviews/${reviewId}/helpful`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ userId: currentUserId || 9 }),
      }),
    onSuccess: () => {
      toast({
        title: "Thank you for your feedback",
        description: "Review marked as helpful!",
      });
      queryClient.invalidateQueries({ queryKey: ['/api/stores', storeId, 'reviews'] });
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to mark review as helpful.",
        variant: "destructive",
      });
    },
  });

  const onSubmit = (data: ReviewFormData) => {
    console.log('Form data being submitted:', data);
    
    const reviewData = {
      ...data,
      rating: selectedRating || data.rating,
      storeId,
      customerId: currentUserId || 9,
    };
    
    console.log('Review data with store info:', reviewData);
    createReviewMutation.mutate(reviewData);
  };

  const handleRatingClick = (rating: number) => {
    setSelectedRating(rating);
    form.setValue('rating', rating);
  };

  const handleMarkHelpful = (reviewId: number) => {
    markHelpfulMutation.mutate(reviewId);
  };

  const averageRating = reviews && reviews.length > 0 
    ? reviews.reduce((sum: number, review: StoreReview) => sum + (review.rating || 0), 0) / reviews.length 
    : 0;

  const ratingDistribution = [5, 4, 3, 2, 1].map(rating => {
    const matchingReviews = reviews ? reviews.filter((review: StoreReview) => review.rating === rating) : [];
    const count = matchingReviews.length;
    const percentage = reviews && reviews.length > 0 ? (count / reviews.length) * 100 : 0;
    
    return {
      rating,
      count,
      percentage
    };
  });

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="animate-pulse">
          <div className="h-8 bg-gray-200 rounded w-48 mb-4"></div>
          <div className="space-y-3">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-32 bg-gray-200 rounded"></div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Compact Rating Summary */}
      <div className="bg-white border border-gray-200 rounded-lg">
        {/* Header with Rating Button */}
        <div className="border-b border-gray-200 p-3 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-gray-900">
            Ratings & Reviews
          </h2>
          <Dialog open={isReviewDialogOpen} onOpenChange={setIsReviewDialogOpen}>
            <DialogTrigger asChild>
              <Button size="sm" className="bg-orange-500 hover:bg-orange-600 text-white px-4" data-rate-store>
                Write Review
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-[500px]">
              <DialogHeader>
                <DialogTitle className="text-xl">Rate This Store</DialogTitle>
              </DialogHeader>
              <Form {...form}>
                <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
                  <FormField
                    control={form.control}
                    name="rating"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel className="text-base font-medium">How would you rate this store?</FormLabel>
                        <FormControl>
                          <div className="flex items-center space-x-2 py-2">
                            {[1, 2, 3, 4, 5].map((star) => (
                              <button
                                key={star}
                                type="button"
                                onClick={() => handleRatingClick(star)}
                                className="focus:outline-none transition-transform hover:scale-110"
                              >
                                <Star
                                  className={`w-10 h-10 ${
                                    star <= selectedRating
                                      ? 'fill-orange-400 text-orange-400'
                                      : 'text-gray-300 hover:text-orange-300'
                                  }`}
                                />
                              </button>
                            ))}
                            {selectedRating > 0 && (
                              <span className="ml-3 text-sm text-gray-600 font-medium">
                                {selectedRating === 5 ? 'Excellent!' : 
                                 selectedRating === 4 ? 'Very Good' : 
                                 selectedRating === 3 ? 'Good' : 
                                 selectedRating === 2 ? 'Fair' : 'Poor'}
                              </span>
                            )}
                          </div>
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="title"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel className="text-base font-medium">Review Title</FormLabel>
                        <FormControl>
                          <Input 
                            placeholder="Summarize your experience in one line" 
                            className="h-12"
                            {...field} 
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="comment"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel className="text-base font-medium">Your Review</FormLabel>
                        <FormControl>
                          <Textarea
                            placeholder="Tell others about your experience with this store..."
                            className="min-h-[120px] resize-none"
                            {...field}
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <div className="flex justify-end space-x-3 pt-4">
                    <Button 
                      type="button" 
                      variant="outline" 
                      className="px-6"
                      onClick={() => setIsReviewDialogOpen(false)}
                    >
                      Cancel
                    </Button>
                    <Button 
                      type="submit" 
                      className="bg-orange-500 hover:bg-orange-600 px-6"
                      disabled={createReviewMutation.isPending || selectedRating === 0}
                    >
                      {createReviewMutation.isPending ? "Publishing..." : "Publish Review"}
                    </Button>
                  </div>
                </form>
              </Form>
            </DialogContent>
          </Dialog>
        </div>

        {/* Compact Rating Overview */}
        <div className="p-4">
          <div className="flex items-center space-x-6">
            {/* Left: Overall Rating */}
            <div className="text-center">
              <div className="text-3xl font-bold text-green-600 mb-1">
                {averageRating.toFixed(1)}
              </div>
              <div className="flex items-center justify-center mb-1">
                {[1, 2, 3, 4, 5].map((star) => (
                  <Star 
                    key={star}
                    className={`w-4 h-4 ${
                      star <= Math.round(averageRating) 
                        ? 'fill-green-500 text-green-500' 
                        : 'text-gray-300'
                    }`}
                  />
                ))}
              </div>
              <p className="text-sm text-gray-600 font-medium">{reviews.length} Reviews</p>
            </div>

            {/* Right: Rating Distribution */}
            <div className="flex-1">
              <div className="space-y-2">
                {ratingDistribution.map(({ rating, count, percentage }) => (
                  <div key={rating} className="flex items-center space-x-2">
                    <span className="text-xs font-medium text-gray-700 w-6">
                      {rating} ★
                    </span>
                    <div className="flex-1 bg-gray-200 rounded-full h-2">
                      <div
                        className="bg-green-500 h-2 rounded-full transition-all duration-300"
                        style={{ width: `${percentage}%` }}
                      ></div>
                    </div>
                    <span className="text-xs text-gray-600 w-6 text-right">
                      {count}
                    </span>
                    <span className="text-xs text-gray-500 w-10 text-right">
                      ({percentage.toFixed(0)}%)
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Compact Reviews List */}
      <div className="bg-white border border-gray-200 rounded-lg">
        <div className="border-b border-gray-200 p-3">
          <h3 className="text-base font-semibold text-gray-900">Customer Reviews</h3>
        </div>
        
        <div className="divide-y divide-gray-200">
          {!reviews || reviews.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-8">
              <MessageCircle className="w-12 h-12 text-gray-300 mb-3" />
              <h3 className="text-base font-medium text-gray-500 mb-1">No reviews yet</h3>
              <p className="text-sm text-gray-400 text-center max-w-sm">
                Be the first to share your experience
              </p>
            </div>
          ) : (
            <>
              {displayedReviews.map((review: StoreReview) => (
              <div key={review.id} className="p-4 hover:bg-gray-50 transition-colors">
                {/* Review Header */}
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center space-x-3">
                    <Avatar className="w-8 h-8">
                      <AvatarFallback className="bg-orange-100 text-orange-600 font-medium text-sm">
                        {review.customer?.fullName?.charAt(0)?.toUpperCase() || 
                         review.customer?.username?.charAt(0)?.toUpperCase() || 'U'}
                      </AvatarFallback>
                    </Avatar>
                    <div>
                      <p className="text-sm font-medium text-gray-900">
                        {review.customer?.fullName || review.customer?.username || 'Anonymous'}
                      </p>
                      <div className="flex items-center space-x-2 mt-0.5">
                        <div className="flex items-center">
                          {[1, 2, 3, 4, 5].map((star) => (
                            <Star 
                              key={star}
                              className={`w-3 h-3 ${
                                star <= review.rating 
                                  ? 'fill-orange-400 text-orange-400' 
                                  : 'text-gray-300'
                              }`}
                            />
                          ))}
                        </div>
                        <span className="text-xs text-gray-500">
                          {new Date(review.createdAt).toLocaleDateString('en-US', {
                            year: 'numeric',
                            month: 'short',
                            day: 'numeric'
                          })}
                        </span>
                      </div>
                    </div>
                  </div>
                  
                  {/* Verified Purchase Badge */}
                  {review.isVerifiedPurchase && (
                    <Badge variant="secondary" className="bg-green-50 text-green-700 border-green-200 text-xs">
                      <Shield className="w-3 h-3 mr-1" />
                      Verified
                    </Badge>
                  )}
                </div>

                {/* Review Content */}
                <div className="space-y-2">
                  {review.title && (
                    <h4 className="font-medium text-gray-900 text-sm">
                      {review.title}
                    </h4>
                  )}
                  {review.comment && (
                    <p className="text-gray-700 text-sm leading-relaxed">
                      {review.comment}
                    </p>
                  )}
                </div>

                {/* Review Actions */}
                <div className="flex items-center justify-between mt-3 pt-2 border-t border-gray-100">
                  <button
                    onClick={() => handleMarkHelpful(review.id)}
                    disabled={markHelpfulMutation.isPending}
                    className="flex items-center space-x-1 text-xs text-gray-600 hover:text-orange-600 transition-colors disabled:opacity-50"
                  >
                    <ThumbsUp className="w-3 h-3" />
                    <span>Helpful</span>
                    {review.helpfulCount > 0 && (
                      <span className="bg-gray-100 text-gray-700 px-1.5 py-0.5 rounded-full text-xs">
                        {review.helpfulCount}
                      </span>
                    )}
                  </button>
                  
                  <div className="text-xs text-gray-400">
                    <span>Was this helpful?</span>
                  </div>
                </div>
              </div>
              ))}
              
              {/* View All Reviews Button */}
              {reviews.length > 2 && (
                <div className="p-3 bg-gray-50 border-t border-gray-200">
                  <div className="text-center">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setShowAllReviews(!showAllReviews)}
                      className="px-4 py-1 border-orange-200 text-orange-600 hover:bg-orange-50 hover:border-orange-300 text-sm"
                    >
                      {showAllReviews ? (
                        <>Show Less</>
                      ) : (
                        <>View All {reviews.length} Reviews</>
                      )}
                    </Button>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}